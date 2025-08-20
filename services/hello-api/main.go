package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	reqTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests",
		},
		[]string{"service", "method", "path", "code"},
	)

	reqDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request duration seconds",
			Buckets: prometheus.DefBuckets, // provides *_bucket series
		},
		[]string{"service", "method", "path"},
	)
)

const serviceName = "hello-api"

func metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		dur := time.Since(start).Seconds()

		labels := prometheus.Labels{"service": serviceName, "method": r.Method, "path": r.URL.Path}
		reqDuration.With(labels).Observe(dur)
		reqTotal.With(prometheus.Labels{"service": serviceName, "method": r.Method, "path": r.URL.Path, "code": strconv.Itoa(rw.status)}).Inc()
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "hello from %s\n", serviceName)
}

func sleepHandler(w http.ResponseWriter, r *http.Request) {
	msStr := r.URL.Query().Get("ms")
	ms, _ := strconv.Atoi(msStr)
	if ms <= 0 {
		ms = 100
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
	fmt.Fprintf(w, "slept %d ms\n", ms)
}

func errorHandler(w http.ResponseWriter, r *http.Request) {
	// 50% chance to return 500
	if rand.Intn(2) == 0 {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "sometimes errors happen\n")
}

func main() {
	rand.Seed(time.Now().UnixNano())
	prometheus.MustRegister(reqTotal, reqDuration)

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/sleep", sleepHandler)
	mux.HandleFunc("/error", errorHandler)
	mux.Handle("/metrics", promhttp.Handler())

	addr := ":8080"
	log.Printf("%s listening on %s", serviceName, addr)
	if err := http.ListenAndServe(addr, metricsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
