package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/stblassitude/bacnet-ip-rest-proxy/internal/bacnet"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// writeBACnetError classifies an error returned from a bacnet.Client call
// and writes the appropriate HTTP status and JSON error body.
func writeBACnetError(w http.ResponseWriter, err error) {
	var bacErr *bacnet.BACnetError
	if errors.As(err, &bacErr) {
		status := http.StatusBadGateway
		switch bacErr.Code {
		case bacnet.ErrorCodeUnknownObject, bacnet.ErrorCodeUnknownProperty:
			status = http.StatusNotFound
		case bacnet.ErrorCodeWriteAccessDenied:
			status = http.StatusForbidden
		case bacnet.ErrorCodeValueOutOfRange:
			status = http.StatusUnprocessableEntity
		case bacnet.ErrorCodeTimeout:
			status = http.StatusGatewayTimeout
		}
		writeJSON(w, status, errorBody{
			Error:            bacErr.Error(),
			BACnetErrorClass: fmt.Sprintf("%d", bacErr.Class),
			BACnetErrorCode:  fmt.Sprintf("%d", bacErr.Code),
		})
		return
	}

	var rejErr *bacnet.RejectError
	if errors.As(err, &rejErr) {
		writeError(w, http.StatusBadGateway, rejErr.Error())
		return
	}

	var abortErr *bacnet.AbortError
	if errors.As(err, &abortErr) {
		writeError(w, http.StatusBadGateway, abortErr.Error())
		return
	}

	if errors.Is(err, bacnet.ErrTimeout) {
		writeError(w, http.StatusGatewayTimeout, "bacnet device did not respond in time")
		return
	}

	writeError(w, http.StatusBadGateway, err.Error())
}
