package handlers

// The shapeMillicores logic and the bulk of the billing-event payload
// shaping moved into internal/billingemit/emitter.go when emit became
// atomic with the status-mutation tx. The unit test that used to live
// here is now in internal/billingemit/emitter_test.go (alongside the
// Emitter that owns the logic).
