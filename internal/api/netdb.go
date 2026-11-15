package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/majestrate/vibecollector/internal/netdb"
	"github.com/majestrate/vibecollector/internal/store"
)

func (s *Server) netdbRoutes() {
	p := s.prefix
	s.mux.HandleFunc("GET "+p+"/protocols", s.withClient(s.listProtocols))
	s.mux.HandleFunc("POST "+p+"/protocols", s.withClient(s.createProtocol))
	s.mux.HandleFunc("GET "+p+"/protocols/{name}", s.withClient(s.getProtocol))
	s.mux.HandleFunc("PUT "+p+"/protocols/{name}", s.withClient(s.putProtocol))
	s.mux.HandleFunc("DELETE "+p+"/protocols/{name}", s.withClient(s.deleteProtocol))
	s.mux.HandleFunc("GET "+p+"/protocol", s.withClient(s.lookupProtocol))
	s.mux.HandleFunc("GET "+p+"/services", s.withClient(s.listServices))
	s.mux.HandleFunc("POST "+p+"/services", s.withClient(s.createService))
	s.mux.HandleFunc("GET "+p+"/services/{name}/{transport}", s.withClient(s.getService))
	s.mux.HandleFunc("PUT "+p+"/services/{name}/{transport}", s.withClient(s.putService))
	s.mux.HandleFunc("DELETE "+p+"/services/{name}/{transport}", s.withClient(s.deleteService))
	s.mux.HandleFunc("GET "+p+"/service", s.withClient(s.lookupService))
}

// withClient runs fn for the oauth client stored on the bearer.
// A missing or rejected token is 401. fn's clientID is that client and is
// the only scope the handler may read or write.
func (s *Server) withClient(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		tok, ok := bearerToken(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id, ok := s.bearerClient(tok)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		fn(w, r, id)
	}
}

func (s *Server) listProtocols(w http.ResponseWriter, r *http.Request, clientID string) {
	rows, err := s.clients.ListClientProtocols(r.Context(), clientID)
	if err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"protocols": protocolList(rows)})
}

func (s *Server) createProtocol(w http.ResponseWriter, r *http.Request, clientID string) {
	var body struct {
		Name    string   `json:"name"`
		Number  *int     `json:"number"`
		Aliases []string `json:"aliases"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Number == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	p := netdb.Protocol{Name: body.Name, Number: *body.Number, Aliases: body.Aliases}
	if err := s.clients.CreateClientProtocol(r.Context(), clientID, p); err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, protocolJSON(p))
}

func (s *Server) getProtocol(w http.ResponseWriter, r *http.Request, clientID string) {
	row, err := s.clients.GetClientProtocol(r.Context(), clientID, r.PathValue("name"))
	if err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocolJSON(row))
}

func (s *Server) putProtocol(w http.ResponseWriter, r *http.Request, clientID string) {
	var body struct {
		Number  *int     `json:"number"`
		Aliases []string `json:"aliases"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Number == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	p := netdb.Protocol{Name: r.PathValue("name"), Number: *body.Number, Aliases: body.Aliases}
	if err := s.clients.UpdateClientProtocol(r.Context(), clientID, p); err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocolJSON(p))
}

func (s *Server) deleteProtocol(w http.ResponseWriter, r *http.Request, clientID string) {
	if err := s.clients.DeleteClientProtocol(r.Context(), clientID, r.PathValue("name")); err != nil {
		writeNetErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) lookupProtocol(w http.ResponseWriter, r *http.Request, clientID string) {
	db, err := s.clientNetDB(r, clientID)
	if err != nil {
		writeNetErr(w, err)
		return
	}
	name := r.URL.Query().Get("name")
	numberText := r.URL.Query().Get("number")
	if (name == "") == (numberText == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	var row netdb.Protocol
	if name != "" {
		row, err = db.ProtocolByName(name)
	} else {
		n, conv := strconv.Atoi(numberText)
		if conv != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
			return
		}
		row, err = db.ProtocolByNumber(n)
	}
	if err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, protocolJSON(row))
}

func (s *Server) listServices(w http.ResponseWriter, r *http.Request, clientID string) {
	rows, err := s.clients.ListClientServices(r.Context(), clientID)
	if err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": serviceList(rows)})
}

func (s *Server) createService(w http.ResponseWriter, r *http.Request, clientID string) {
	var body struct {
		Name     string   `json:"name"`
		Port     *int     `json:"port"`
		Protocol string   `json:"protocol"`
		Aliases  []string `json:"aliases"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Port == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	svc := netdb.Service{Name: body.Name, Port: *body.Port, Protocol: body.Protocol, Aliases: body.Aliases}
	if err := s.clients.CreateClientService(r.Context(), clientID, svc); err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, serviceJSON(svc))
}

func (s *Server) getService(w http.ResponseWriter, r *http.Request, clientID string) {
	row, err := s.clients.GetClientService(r.Context(), clientID, r.PathValue("name"), r.PathValue("transport"))
	if err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, serviceJSON(row))
}

func (s *Server) putService(w http.ResponseWriter, r *http.Request, clientID string) {
	var body struct {
		Port    *int     `json:"port"`
		Aliases []string `json:"aliases"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Port == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	svc := netdb.Service{
		Name: r.PathValue("name"), Port: *body.Port, Protocol: r.PathValue("transport"), Aliases: body.Aliases,
	}
	if err := s.clients.UpdateClientService(r.Context(), clientID, svc); err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, serviceJSON(svc))
}

func (s *Server) deleteService(w http.ResponseWriter, r *http.Request, clientID string) {
	if err := s.clients.DeleteClientService(r.Context(), clientID, r.PathValue("name"), r.PathValue("transport")); err != nil {
		writeNetErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) lookupService(w http.ResponseWriter, r *http.Request, clientID string) {
	db, err := s.clientNetDB(r, clientID)
	if err != nil {
		writeNetErr(w, err)
		return
	}
	q := r.URL.Query()
	name := q.Get("name")
	portText := q.Get("port")
	proto := q.Get("protocol")
	if (name == "") == (portText == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	var row netdb.Service
	if name != "" {
		row, err = db.ServiceByName(name, proto)
	} else {
		port, conv := strconv.Atoi(portText)
		if conv != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
			return
		}
		row, err = db.ServiceByPort(port, proto)
	}
	if err != nil {
		writeNetErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, serviceJSON(row))
}

// clientNetDB loads the system tables with this client's rows appended.
// clientID selects the override. The filesystem opens only the two table
// paths. A read error is returned to the caller.
func (s *Server) clientNetDB(r *http.Request, clientID string) (*netdb.DB, error) {
	fsys := store.NewNetFS(r.Context(), s.clients, clientID, os.DirFS("/"))
	return netdb.Load(fsys, netdb.ProtocolsPath, netdb.ServicesPath)
}

func readJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return false
	}
	return true
}

func writeNetErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNetEntry), errors.Is(err, store.ErrBadClient):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
	case errors.Is(err, store.ErrNetExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "exists"})
	case errors.Is(err, store.ErrNetAbsent), errors.Is(err, netdb.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}
}

type protocolBody struct {
	Name    string   `json:"name"`
	Number  int      `json:"number"`
	Aliases []string `json:"aliases"`
}

type serviceBody struct {
	Name     string   `json:"name"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Aliases  []string `json:"aliases"`
}

func protocolJSON(p netdb.Protocol) protocolBody {
	if p.Aliases == nil {
		p.Aliases = []string{}
	}
	return protocolBody{Name: p.Name, Number: p.Number, Aliases: p.Aliases}
}

func serviceJSON(svc netdb.Service) serviceBody {
	if svc.Aliases == nil {
		svc.Aliases = []string{}
	}
	return serviceBody{Name: svc.Name, Port: svc.Port, Protocol: svc.Protocol, Aliases: svc.Aliases}
}

func protocolList(rows []netdb.Protocol) []protocolBody {
	out := make([]protocolBody, len(rows))
	for i, row := range rows {
		out[i] = protocolJSON(row)
	}
	return out
}

func serviceList(rows []netdb.Service) []serviceBody {
	out := make([]serviceBody, len(rows))
	for i, row := range rows {
		out[i] = serviceJSON(row)
	}
	return out
}
