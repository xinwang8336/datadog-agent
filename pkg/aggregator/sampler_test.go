package aggregator

import (
	// stdlib
	"fmt"
	"math"
	"sort"
	"testing"

	// 3p
	"github.com/stretchr/testify/assert"
)

// Helper(s)
func AssertSerieEqual(t *testing.T, expected, actual *Serie) {
	assert.Equal(t, expected.Name, actual.Name)
	if expected.Tags != nil {
		assert.NotNil(t, actual.Tags)
		AssertTagsEqual(t, expected.Tags, actual.Tags)
	}
	assert.Equal(t, expected.Host, actual.Host)
	assert.Equal(t, expected.DeviceName, actual.DeviceName)
	assert.Equal(t, expected.MType, actual.MType)
	assert.Equal(t, expected.Interval, actual.Interval)
	if expected.contextKey != "" {
		// Only test the contextKey if it's set in the expected Serie
		assert.Equal(t, expected.contextKey, actual.contextKey)
	}
	assert.Equal(t, expected.nameSuffix, actual.nameSuffix)
	AssertPointsEqual(t, expected.Points, actual.Points)
}

func AssertTagsEqual(t *testing.T, expected, actual []string) {
	if assert.Equal(t, len(expected), len(actual), fmt.Sprintf("Unexpected number of tags: expected %s, actual: %s", expected, actual)) {
		for _, tag := range expected {
			assert.Contains(t, actual, tag)
		}
	}
}

func AssertPointsEqual(t *testing.T, expected, actual []Point) {
	if assert.Equal(t, len(expected), len(actual)) {
		for _, point := range expected {
			assert.Contains(t, actual, point)
		}
	}
}

type OrderedSeries struct {
	series []*Serie
}

func (os OrderedSeries) Len() int {
	return len(os.series)
}

func (os OrderedSeries) Less(i, j int) bool {
	return os.series[i].contextKey < os.series[j].contextKey
}

func (os OrderedSeries) Swap(i, j int) {
	os.series[j], os.series[i] = os.series[i], os.series[j]
}

// Metrics
func TestMetricsGaugeSampling(t *testing.T) {
	metrics := makeMetrics()
	contextKey := "context_key"
	mSample := MetricSample{
		Value: 1,
		Mtype: GaugeType,
	}

	metrics.addSample(contextKey, mSample.Mtype, mSample.Value, 1)
	series := metrics.flush(12345)

	expectedSerie := &Serie{
		contextKey: contextKey,
		Points:     []Point{{int64(12345), mSample.Value}},
		MType:      APIGaugeType,
		nameSuffix: "",
	}

	if assert.Equal(t, 1, len(series)) {
		AssertSerieEqual(t, expectedSerie, series[0])
	}
}

// No series should be flushed when there's no new sample btw 2 flushes
// Important for check metrics aggregation
func TestMetricsGaugeSamplingNoSample(t *testing.T) {
	metrics := makeMetrics()
	contextKey := "context_key"
	mSample := MetricSample{
		Value: 1,
		Mtype: GaugeType,
	}

	metrics.addSample(contextKey, mSample.Mtype, mSample.Value, 1)
	series := metrics.flush(12345)

	assert.Equal(t, 1, len(series))

	series = metrics.flush(12355)
	// No series flushed since there's no new sample since last flush
	assert.Equal(t, 0, len(series))
}

// No series should be flushed when the samples have values of +Inf/-Inf
func TestMetricsGaugeSamplingInfinity(t *testing.T) {
	metrics := makeMetrics()
	contextKey1 := "context_key1"
	contextKey2 := "context_key2"
	mSample1 := MetricSample{
		Value: math.Inf(1),
		Mtype: GaugeType,
	}
	mSample2 := MetricSample{
		Value: math.Inf(-1),
		Mtype: GaugeType,
	}

	metrics.addSample(contextKey1, mSample1.Mtype, mSample1.Value, 1)
	metrics.addSample(contextKey2, mSample2.Mtype, mSample2.Value, 1)
	series := metrics.flush(12345)

	assert.Equal(t, 0, len(series))
}

// No series should be flushed when the rate has been sampled only once overall
// Important for check metrics aggregation
func TestMetricsRateSampling(t *testing.T) {
	metrics := makeMetrics()
	contextKey := "context_key"

	metrics.addSample(contextKey, RateType, 1, 12340)
	series := metrics.flush(12345)

	// No series flushed since the rate was sampled once only
	assert.Equal(t, 0, len(series))

	metrics.addSample(contextKey, RateType, 2, 12350)
	series = metrics.flush(12351)
	expectedSerie := &Serie{
		contextKey: contextKey,
		Points:     []Point{{int64(12350), 1. / 10.}},
		MType:      APIGaugeType,
		nameSuffix: "",
	}

	if assert.Equal(t, 1, len(series)) {
		AssertSerieEqual(t, expectedSerie, series[0])
	}
}

func TestMetricsHistogramSampling(t *testing.T) {
	metrics := makeMetrics()
	contextKey := "context_key"

	metrics.addSample(contextKey, HistogramType, 1, 12340)
	metrics.addSample(contextKey, HistogramType, 2, 12342)
	metrics.addSample(contextKey, HistogramType, 1, 12350)
	metrics.addSample(contextKey, HistogramType, 6, 12350)
	series := metrics.flush(12351)

	expectedSeries := []*Serie{
		&Serie{
			contextKey: contextKey,
			Points:     []Point{{int64(12351), 6.}},
			MType:      APIGaugeType,
			nameSuffix: ".max",
		},
		&Serie{
			contextKey: contextKey,
			Points:     []Point{{int64(12351), 1.}},
			MType:      APIGaugeType,
			nameSuffix: ".median",
		},
		&Serie{
			contextKey: contextKey,
			Points:     []Point{{int64(12351), 2.5}},
			MType:      APIGaugeType,
			nameSuffix: ".avg",
		},
		&Serie{
			contextKey: contextKey,
			Points:     []Point{{int64(12351), 4.}},
			MType:      APIRateType,
			nameSuffix: ".count",
		},
		&Serie{
			contextKey: contextKey,
			Points:     []Point{{int64(12351), 6.}},
			MType:      APIGaugeType,
			nameSuffix: ".95percentile",
		},
	}

	if assert.Len(t, series, len(expectedSeries)) {
		for i := range expectedSeries {
			AssertSerieEqual(t, expectedSeries[i], series[i])
		}
	}
}

// Sampler
func TestCalculateBucketStart(t *testing.T) {
	sampler := NewSampler(10)

	assert.Equal(t, int64(123450), sampler.calculateBucketStart(123456))
	assert.Equal(t, int64(123460), sampler.calculateBucketStart(123460))

}

func TestBucketSampling(t *testing.T) {
	sampler := NewSampler(10)

	mSample := MetricSample{
		Name:       "my.metric.name",
		Value:      1,
		Mtype:      GaugeType,
		Tags:       &[]string{"foo", "bar"},
		SampleRate: 1,
	}
	sampler.addSample(&mSample, 12345)
	sampler.addSample(&mSample, 12355)
	sampler.addSample(&mSample, 12365)

	series := sampler.flush(12360)

	expectedSerie := &Serie{
		Name:       "my.metric.name",
		Tags:       []string{"foo", "bar"},
		Points:     []Point{{int64(12340), mSample.Value}, {int64(12350), mSample.Value}},
		MType:      APIGaugeType,
		Interval:   10,
		nameSuffix: "",
	}

	assert.Equal(t, 1, len(sampler.metricsByTimestamp))
	if assert.Equal(t, 1, len(series)) {
		AssertSerieEqual(t, expectedSerie, series[0])
	}
}

func TestContextSampling(t *testing.T) {
	sampler := NewSampler(10)

	mSample1 := MetricSample{
		Name:       "my.metric.name1",
		Value:      1,
		Mtype:      GaugeType,
		Tags:       &[]string{"foo", "bar"},
		SampleRate: 1,
	}
	mSample2 := MetricSample{
		Name:       "my.metric.name2",
		Value:      1,
		Mtype:      GaugeType,
		Tags:       &[]string{"foo", "bar"},
		SampleRate: 1,
	}

	sampler.addSample(&mSample1, 12346)
	sampler.addSample(&mSample2, 12346)

	orderedSeries := OrderedSeries{sampler.flush(12360)}
	sort.Sort(orderedSeries)

	series := orderedSeries.series

	expectedSerie1 := &Serie{
		Name:     "my.metric.name1",
		Points:   []Point{{int64(12340), float64(1)}},
		Tags:     []string{"bar", "foo"},
		MType:    APIGaugeType,
		Interval: 10,
	}
	expectedSerie2 := &Serie{
		Name:     "my.metric.name2",
		Points:   []Point{{int64(12340), float64(1)}},
		Tags:     []string{"bar", "foo"},
		MType:    APIGaugeType,
		Interval: 10,
	}

	if assert.Equal(t, 2, len(series)) {
		AssertSerieEqual(t, expectedSerie1, series[0])
		AssertSerieEqual(t, expectedSerie2, series[1])
	}
}

//func TestOne(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestFormatter(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestCounterNormalization(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestHistogramNormalization(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestCounter(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestSampledCounter(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestGauge(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestSets(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestStringSets(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestRate(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestRateErrors(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestGaugeSampleRate(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestHistogram(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestSampledHistogram(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestBatchSubmission(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestMonokeyBatchingNoTags(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestMonokeyBatchingWithTags(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestMonokeyBatchingWithTagsWithSampling(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestBadPacketsThrowErrors(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestMetricsExpiry(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestDiagnosticStats(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestHistogramCounter(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestEventTags(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestServiceCheckBasic(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestServiceCheckTags(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
//
//func TestRecentPointThreshold(t *testing.T) {
//	assert.Equal(t, 1, 1)
//}
