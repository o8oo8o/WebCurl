package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var (
	// ErrMethodMismatch is returned when the method in the request does not match
	// the method defined against the route.
	ErrMethodMismatch = errors.New("method is not allowed")
	// ErrNotFound is returned when no route match is found.
	ErrNotFound = errors.New("no matching route was found")
)

// NewRouter returns a new router instance.
func NewRouter() *Router {
	return &Router{namedRoutes: make(map[string]*Route)}
}

// Router registers routes to be matched and dispatches a handler.
//
// It implements the http.Handler interface, so it can be registered to serve
// requests:
//
//	var router = mux.NewRouter()
//
//	func main() {
//	    http.Handle("/", router)
//	}
//
// Or, for Google App Engine, register it in a init() function:
//
//	func init() {
//	    http.Handle("/", router)
//	}
//
// This will send all incoming requests to the router.
type Router struct {
	// Configurable Handler to be used when no route matches.
	// This can be used to render your own 404 Not Found errors.
	NotFoundHandler http.Handler

	// Configurable Handler to be used when the request method does not match the route.
	// This can be used to render your own 405 Method Not Allowed errors.
	MethodNotAllowedHandler http.Handler

	// Routes to be matched, in order.
	routes []*Route

	// Routes by name for URL building.
	namedRoutes map[string]*Route

	// If true, do not clear the request context after handling the request.
	//
	// Deprecated: No effect, since the context is stored on the request itself.
	KeepContext bool

	// Slice of middlewares to be called after a match is found
	middlewares []middleware

	// configuration shared with `Route`
	routeConf
}

// common route configuration shared between `Router` and `Route`
type routeConf struct {
	// If true, "/path/foo%2Fbar/to" will match the path "/path/{var}/to"
	useEncodedPath bool

	// If true, when the path pattern is "/path/", accessing "/path" will
	// redirect to the former and vice versa.
	strictSlash bool

	// If true, when the path pattern is "/path//to", accessing "/path//to"
	// will not redirect
	skipClean bool

	// Manager for the variables from host and path.
	regexp routeRegexpGroup

	// List of matchers.
	matchers []matcher

	// The scheme used when building URLs.
	buildScheme string

	buildVarsFunc BuildVarsFunc
}

// returns an effective deep copy of `routeConf`
func copyRouteConf(r routeConf) routeConf {
	c := r

	if r.regexp.path != nil {
		c.regexp.path = copyRouteRegexp(r.regexp.path)
	}

	if r.regexp.host != nil {
		c.regexp.host = copyRouteRegexp(r.regexp.host)
	}

	c.regexp.queries = make([]*routeRegexp, 0, len(r.regexp.queries))
	for _, q := range r.regexp.queries {
		c.regexp.queries = append(c.regexp.queries, copyRouteRegexp(q))
	}

	c.matchers = make([]matcher, len(r.matchers))
	copy(c.matchers, r.matchers)

	return c
}

func copyRouteRegexp(r *routeRegexp) *routeRegexp {
	c := *r
	return &c
}

// Match attempts to match the given request against the router's registered routes.
//
// If the request matches a route of this router or one of its subrouters the Route,
// Handler, and Vars fields of the the match argument are filled and this function
// returns true.
//
// If the request does not match any of this router's or its subrouters' routes
// then this function returns false. If available, a reason for the match failure
// will be filled in the match argument's MatchErr field. If the match failure type
// (eg: not found) has a registered handler, the handler is assigned to the Handler
// field of the match argument.
func (r *Router) Match(req *http.Request, match *RouteMatch) bool {
	for _, route := range r.routes {
		if route.Match(req, match) {
			// Build middleware chain if no error was found
			if match.MatchErr == nil {
				for i := len(r.middlewares) - 1; i >= 0; i-- {
					match.Handler = r.middlewares[i].Middleware(match.Handler)
				}
			}
			return true
		}
	}

	if match.MatchErr == ErrMethodMismatch {
		if r.MethodNotAllowedHandler != nil {
			match.Handler = r.MethodNotAllowedHandler
			return true
		}

		return false
	}

	// Closest match for a router (includes sub-routers)
	if r.NotFoundHandler != nil {
		match.Handler = r.NotFoundHandler
		match.MatchErr = ErrNotFound
		return true
	}

	match.MatchErr = ErrNotFound
	return false
}

// ServeHTTP dispatches the handler registered in the matched route.
//
// When there is a match, the route variables can be retrieved calling
// mux.Vars(request).
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !r.skipClean {
		path := req.URL.Path
		if r.useEncodedPath {
			path = req.URL.EscapedPath()
		}
		// Clean path to canonical form and redirect.
		if p := cleanPath(path); p != path {

			// Added 3 lines (Philip Schlump) - It was dropping the query string and #whatever from query.
			// This matches with fix in go 1.2 r.c. 4 for same problem.  Go Issue:
			// http://code.google.com/p/go/issues/detail?id=5252
			url := *req.URL
			url.Path = p
			p = url.String()

			w.Header().Set("Location", p)
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
	}
	var match RouteMatch
	var handler http.Handler
	if r.Match(req, &match) {
		handler = match.Handler
		req = requestWithVars(req, match.Vars)
		req = requestWithRoute(req, match.Route)
	}

	if handler == nil && match.MatchErr == ErrMethodMismatch {
		handler = methodNotAllowedHandler()
	}

	if handler == nil {
		handler = http.NotFoundHandler()
	}

	handler.ServeHTTP(w, req)
}

// Get returns a route registered with the given name.
func (r *Router) Get(name string) *Route {
	return r.namedRoutes[name]
}

// GetRoute returns a route registered with the given name. This method
// was renamed to Get() and remains here for backwards compatibility.
func (r *Router) GetRoute(name string) *Route {
	return r.namedRoutes[name]
}

// StrictSlash defines the trailing slash behavior for new routes. The initial
// value is false.
//
// When true, if the route path is "/path/", accessing "/path" will perform a redirect
// to the former and vice versa. In other words, your application will always
// see the path as specified in the route.
//
// When false, if the route path is "/path", accessing "/path/" will not match
// this route and vice versa.
//
// The re-direct is a HTTP 301 (Moved Permanently). Note that when this is set for
// routes with a non-idempotent method (e.g. POST, PUT), the subsequent re-directed
// request will be made as a GET by most clients. Use middleware or client settings
// to modify this behaviour as needed.
//
// Special case: when a route sets a path prefix using the PathPrefix() method,
// strict slash is ignored for that route because the redirect behavior can't
// be determined from a prefix alone. However, any subrouters created from that
// route inherit the original StrictSlash setting.
func (r *Router) StrictSlash(value bool) *Router {
	r.strictSlash = value
	return r
}

// SkipClean defines the path cleaning behaviour for new routes. The initial
// value is false. Users should be careful about which routes are not cleaned
//
// When true, if the route path is "/path//to", it will remain with the double
// slash. This is helpful if you have a route like: /fetch/http://xkcd.com/534/
//
// When false, the path will be cleaned, so /fetch/http://xkcd.com/534/ will
// become /fetch/http/xkcd.com/534
func (r *Router) SkipClean(value bool) *Router {
	r.skipClean = value
	return r
}

// UseEncodedPath tells the router to match the encoded original path
// to the routes.
// For eg. "/path/foo%2Fbar/to" will match the path "/path/{var}/to".
//
// If not called, the router will match the unencoded path to the routes.
// For eg. "/path/foo%2Fbar/to" will match the path "/path/foo/bar/to"
func (r *Router) UseEncodedPath() *Router {
	r.useEncodedPath = true
	return r
}

// ----------------------------------------------------------------------------
// Route factories
// ----------------------------------------------------------------------------

// NewRoute registers an empty route.
func (r *Router) NewRoute() *Route {
	// initialize a route with a copy of the parent router's configuration
	route := &Route{routeConf: copyRouteConf(r.routeConf), namedRoutes: r.namedRoutes}
	r.routes = append(r.routes, route)
	return route
}

// Name registers a new route with a name.
// See Route.Name().
func (r *Router) Name(name string) *Route {
	return r.NewRoute().Name(name)
}

// Handle registers a new route with a matcher for the URL path.
// See Route.Path() and Route.Handler().
func (r *Router) Handle(path string, handler http.Handler) *Route {
	return r.NewRoute().Path(path).Handler(handler)
}

// HandleFunc registers a new route with a matcher for the URL path.
// See Route.Path() and Route.HandlerFunc().
func (r *Router) HandleFunc(path string, f func(http.ResponseWriter,
	*http.Request)) *Route {
	return r.NewRoute().Path(path).HandlerFunc(f)
}

// Headers registers a new route with a matcher for request header values.
// See Route.Headers().
func (r *Router) Headers(pairs ...string) *Route {
	return r.NewRoute().Headers(pairs...)
}

// Host registers a new route with a matcher for the URL host.
// See Route.Host().
func (r *Router) Host(tpl string) *Route {
	return r.NewRoute().Host(tpl)
}

// MatcherFunc registers a new route with a custom matcher function.
// See Route.MatcherFunc().
func (r *Router) MatcherFunc(f MatcherFunc) *Route {
	return r.NewRoute().MatcherFunc(f)
}

// Methods registers a new route with a matcher for HTTP methods.
// See Route.Methods().
func (r *Router) Methods(methods ...string) *Route {
	return r.NewRoute().Methods(methods...)
}

// Path registers a new route with a matcher for the URL path.
// See Route.Path().
func (r *Router) Path(tpl string) *Route {
	return r.NewRoute().Path(tpl)
}

// PathPrefix registers a new route with a matcher for the URL path prefix.
// See Route.PathPrefix().
func (r *Router) PathPrefix(tpl string) *Route {
	return r.NewRoute().PathPrefix(tpl)
}

// Queries registers a new route with a matcher for URL query values.
// See Route.Queries().
func (r *Router) Queries(pairs ...string) *Route {
	return r.NewRoute().Queries(pairs...)
}

// Schemes registers a new route with a matcher for URL schemes.
// See Route.Schemes().
func (r *Router) Schemes(schemes ...string) *Route {
	return r.NewRoute().Schemes(schemes...)
}

// BuildVarsFunc registers a new route with a custom function for modifying
// route variables before building a URL.
func (r *Router) BuildVarsFunc(f BuildVarsFunc) *Route {
	return r.NewRoute().BuildVarsFunc(f)
}

// Walk walks the router and all its sub-routers, calling walkFn for each route
// in the tree. The routes are walked in the order they were added. Sub-routers
// are explored depth-first.
func (r *Router) Walk(walkFn WalkFunc) error {
	return r.walk(walkFn, []*Route{})
}

// SkipRouter is used as a return value from WalkFuncs to indicate that the
// router that walk is about to descend down to should be skipped.
var SkipRouter = errors.New("skip this router")

// WalkFunc is the type of the function called for each route visited by Walk.
// At every invocation, it is given the current route, and the current router,
// and a list of ancestor routes that lead to the current route.
type WalkFunc func(route *Route, router *Router, ancestors []*Route) error

func (r *Router) walk(walkFn WalkFunc, ancestors []*Route) error {
	for _, t := range r.routes {
		err := walkFn(t, r, ancestors)
		if err == SkipRouter {
			continue
		}
		if err != nil {
			return err
		}
		for _, sr := range t.matchers {
			if h, ok := sr.(*Router); ok {
				ancestors = append(ancestors, t)
				err := h.walk(walkFn, ancestors)
				if err != nil {
					return err
				}
				ancestors = ancestors[:len(ancestors)-1]
			}
		}
		if h, ok := t.handler.(*Router); ok {
			ancestors = append(ancestors, t)
			err := h.walk(walkFn, ancestors)
			if err != nil {
				return err
			}
			ancestors = ancestors[:len(ancestors)-1]
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Context
// ----------------------------------------------------------------------------

// RouteMatch stores information about a matched route.
type RouteMatch struct {
	Route   *Route
	Handler http.Handler
	Vars    map[string]string

	// MatchErr is set to appropriate matching error
	// It is set to ErrMethodMismatch if there is a mismatch in
	// the request method and route method
	MatchErr error
}

type contextKey int

const (
	varsKey contextKey = iota
	routeKey
)

// Vars returns the route variables for the current request, if any.
func Vars(r *http.Request) map[string]string {
	if rv := r.Context().Value(varsKey); rv != nil {
		return rv.(map[string]string)
	}
	return nil
}

// CurrentRoute returns the matched route for the current request, if any.
// This only works when called inside the handler of the matched route
// because the matched route is stored in the request context which is cleared
// after the handler returns.
func CurrentRoute(r *http.Request) *Route {
	if rv := r.Context().Value(routeKey); rv != nil {
		return rv.(*Route)
	}
	return nil
}

func requestWithVars(r *http.Request, vars map[string]string) *http.Request {
	ctx := context.WithValue(r.Context(), varsKey, vars)
	return r.WithContext(ctx)
}

func requestWithRoute(r *http.Request, route *Route) *http.Request {
	ctx := context.WithValue(r.Context(), routeKey, route)
	return r.WithContext(ctx)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// cleanPath returns the canonical path for p, eliminating . and .. elements.
// Borrowed from the net/http package.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		np += "/"
	}

	return np
}

// uniqueVars returns an error if two slices contain duplicated strings.
func uniqueVars(s1, s2 []string) error {
	for _, v1 := range s1 {
		for _, v2 := range s2 {
			if v1 == v2 {
				return fmt.Errorf("mux: duplicated route variable %q", v2)
			}
		}
	}
	return nil
}

// checkPairs returns the count of strings passed in, and an error if
// the count is not an even number.
func checkPairs(pairs ...string) (int, error) {
	length := len(pairs)
	if length%2 != 0 {
		return length, fmt.Errorf(
			"mux: number of parameters must be multiple of 2, got %v", pairs)
	}
	return length, nil
}

// mapFromPairsToString converts variadic string parameters to a
// string to string map.
func mapFromPairsToString(pairs ...string) (map[string]string, error) {
	length, err := checkPairs(pairs...)
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, length/2)
	for i := 0; i < length; i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return m, nil
}

// mapFromPairsToRegex converts variadic string parameters to a
// string to regex map.
func mapFromPairsToRegex(pairs ...string) (map[string]*regexp.Regexp, error) {
	length, err := checkPairs(pairs...)
	if err != nil {
		return nil, err
	}
	m := make(map[string]*regexp.Regexp, length/2)
	for i := 0; i < length; i += 2 {
		regex, err := regexp.Compile(pairs[i+1])
		if err != nil {
			return nil, err
		}
		m[pairs[i]] = regex
	}
	return m, nil
}

// matchInArray returns true if the given string value is in the array.
func matchInArray(arr []string, value string) bool {
	for _, v := range arr {
		if v == value {
			return true
		}
	}
	return false
}

// matchMapWithString returns true if the given key/value pairs exist in a given map.
func matchMapWithString(toCheck map[string]string, toMatch map[string][]string, canonicalKey bool) bool {
	for k, v := range toCheck {
		// Check if key exists.
		if canonicalKey {
			k = http.CanonicalHeaderKey(k)
		}
		if values := toMatch[k]; values == nil {
			return false
		} else if v != "" {
			// If value was defined as an empty string we only check that the
			// key exists. Otherwise we also check for equality.
			valueExists := false
			for _, value := range values {
				if v == value {
					valueExists = true
					break
				}
			}
			if !valueExists {
				return false
			}
		}
	}
	return true
}

// matchMapWithRegex returns true if the given key/value pairs exist in a given map compiled against
// the given regex
func matchMapWithRegex(toCheck map[string]*regexp.Regexp, toMatch map[string][]string, canonicalKey bool) bool {
	for k, v := range toCheck {
		// Check if key exists.
		if canonicalKey {
			k = http.CanonicalHeaderKey(k)
		}
		if values := toMatch[k]; values == nil {
			return false
		} else if v != nil {
			// If value was defined as an empty string we only check that the
			// key exists. Otherwise we also check for equality.
			valueExists := false
			for _, value := range values {
				if v.MatchString(value) {
					valueExists = true
					break
				}
			}
			if !valueExists {
				return false
			}
		}
	}
	return true
}

// methodNotAllowed replies to the request with an HTTP status code 405.
func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusMethodNotAllowed)
}

// methodNotAllowedHandler returns a simple request handler
// that replies to each request with a status code 405.
func methodNotAllowedHandler() http.Handler { return http.HandlerFunc(methodNotAllowed) }

//----------------------------------------------------------------------------------------------------

// MiddlewareFunc is a function which receives an http.Handler and returns another http.Handler.
// Typically, the returned handler is a closure which does something with the http.ResponseWriter and http.Request passed
// to it, and then calls the handler passed as parameter to the MiddlewareFunc.
type MiddlewareFunc func(http.Handler) http.Handler

// middleware interface is anything which implements a MiddlewareFunc named Middleware.
type middleware interface {
	Middleware(handler http.Handler) http.Handler
}

// Middleware allows MiddlewareFunc to implement the middleware interface.
func (mw MiddlewareFunc) Middleware(handler http.Handler) http.Handler {
	return mw(handler)
}

// Use appends a MiddlewareFunc to the chain. Middleware can be used to intercept or otherwise modify requests and/or responses, and are executed in the order that they are applied to the Router.
func (r *Router) Use(mwf ...MiddlewareFunc) {
	for _, fn := range mwf {
		r.middlewares = append(r.middlewares, fn)
	}
}

// useInterface appends a middleware to the chain. Middleware can be used to intercept or otherwise modify requests and/or responses, and are executed in the order that they are applied to the Router.
func (r *Router) useInterface(mw middleware) {
	r.middlewares = append(r.middlewares, mw)
}

// CORSMethodMiddleware automatically sets the Access-Control-Allow-Methods response header
// on requests for routes that have an OPTIONS method matcher to all the method matchers on
// the route. Routes that do not explicitly handle OPTIONS requests will not be processed
// by the middleware. See examples for usage.
func CORSMethodMiddleware(r *Router) MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			allMethods, err := getAllMethodsForRoute(r, req)
			if err == nil {
				for _, v := range allMethods {
					if v == http.MethodOptions {
						w.Header().Set("Access-Control-Allow-Methods", strings.Join(allMethods, ","))
					}
				}
			}

			next.ServeHTTP(w, req)
		})
	}
}

// getAllMethodsForRoute returns all the methods from method matchers matching a given
// request.
func getAllMethodsForRoute(r *Router, req *http.Request) ([]string, error) {
	var allMethods []string

	for _, route := range r.routes {
		var match RouteMatch
		if route.Match(req, &match) || match.MatchErr == ErrMethodMismatch {
			methods, err := route.GetMethods()
			if err != nil {
				return nil, err
			}

			allMethods = append(allMethods, methods...)
		}
	}

	return allMethods, nil
}

//----------------------------------------------------------------------------------------------------

type routeRegexpOptions struct {
	strictSlash    bool
	useEncodedPath bool
}

type regexpType int

const (
	regexpTypePath regexpType = iota
	regexpTypeHost
	regexpTypePrefix
	regexpTypeQuery
)

// newRouteRegexp parses a route template and returns a routeRegexp,
// used to match a host, a path or a query string.
//
// It will extract named variables, assemble a regexp to be matched, create
// a "reverse" template to build URLs and compile regexps to validate variable
// values used in URL building.
//
// Previously we accepted only Python-like identifiers for variable
// names ([a-zA-Z_][a-zA-Z0-9_]*), but currently the only restriction is that
// name and pattern can't be empty, and names can't contain a colon.
func newRouteRegexp(tpl string, typ regexpType, options routeRegexpOptions) (*routeRegexp, error) {
	// Check if it is well-formed.
	idxs, errBraces := braceIndices(tpl)
	if errBraces != nil {
		return nil, errBraces
	}
	// Backup the original.
	template := tpl
	// Now let's parse it.
	defaultPattern := "[^/]+"
	if typ == regexpTypeQuery {
		defaultPattern = ".*"
	} else if typ == regexpTypeHost {
		defaultPattern = "[^.]+"
	}
	// Only match strict slash if not matching
	if typ != regexpTypePath {
		options.strictSlash = false
	}
	// Set a flag for strictSlash.
	endSlash := false
	if options.strictSlash && strings.HasSuffix(tpl, "/") {
		tpl = tpl[:len(tpl)-1]
		endSlash = true
	}
	varsN := make([]string, len(idxs)/2)
	varsR := make([]*regexp.Regexp, len(idxs)/2)
	pattern := bytes.NewBufferString("")
	pattern.WriteByte('^')
	reverse := bytes.NewBufferString("")
	var end int
	var err error
	for i := 0; i < len(idxs); i += 2 {
		// Set all values we are interested in.
		raw := tpl[end:idxs[i]]
		end = idxs[i+1]
		parts := strings.SplitN(tpl[idxs[i]+1:end-1], ":", 2)
		name := parts[0]
		patt := defaultPattern
		if len(parts) == 2 {
			patt = parts[1]
		}
		// Name or pattern can't be empty.
		if name == "" || patt == "" {
			return nil, fmt.Errorf("mux: missing name or pattern in %q",
				tpl[idxs[i]:end])
		}
		// Build the regexp pattern.
		fmt.Fprintf(pattern, "%s(?P<%s>%s)", regexp.QuoteMeta(raw), varGroupName(i/2), patt)

		// Build the reverse template.
		fmt.Fprintf(reverse, "%s%%s", raw)

		// Append variable name and compiled pattern.
		varsN[i/2] = name
		varsR[i/2], err = regexp.Compile(fmt.Sprintf("^%s$", patt))
		if err != nil {
			return nil, err
		}
	}
	// Add the remaining.
	raw := tpl[end:]
	pattern.WriteString(regexp.QuoteMeta(raw))
	if options.strictSlash {
		pattern.WriteString("[/]?")
	}
	if typ == regexpTypeQuery {
		// Add the default pattern if the query value is empty
		if queryVal := strings.SplitN(template, "=", 2)[1]; queryVal == "" {
			pattern.WriteString(defaultPattern)
		}
	}
	if typ != regexpTypePrefix {
		pattern.WriteByte('$')
	}

	var wildcardHostPort bool
	if typ == regexpTypeHost {
		if !strings.Contains(pattern.String(), ":") {
			wildcardHostPort = true
		}
	}
	reverse.WriteString(raw)
	if endSlash {
		reverse.WriteByte('/')
	}
	// Compile full regexp.
	reg, errCompile := regexp.Compile(pattern.String())
	if errCompile != nil {
		return nil, errCompile
	}

	// Check for capturing groups which used to work in older versions
	if reg.NumSubexp() != len(idxs)/2 {
		panic(fmt.Sprintf("route %s contains capture groups in its regexp. ", template) +
			"Only non-capturing groups are accepted: e.g. (?:pattern) instead of (pattern)")
	}

	// Done!
	return &routeRegexp{
		template:         template,
		regexpType:       typ,
		options:          options,
		regexp:           reg,
		reverse:          reverse.String(),
		varsN:            varsN,
		varsR:            varsR,
		wildcardHostPort: wildcardHostPort,
	}, nil
}

// routeRegexp stores a regexp to match a host or path and information to
// collect and validate route variables.
type routeRegexp struct {
	// The unmodified template.
	template string
	// The type of match
	regexpType regexpType
	// Options for matching
	options routeRegexpOptions
	// Expanded regexp.
	regexp *regexp.Regexp
	// Reverse template.
	reverse string
	// Variable names.
	varsN []string
	// Variable regexps (validators).
	varsR []*regexp.Regexp
	// Wildcard host-port (no strict port match in hostname)
	wildcardHostPort bool
}

// Match matches the regexp against the URL host or path.
func (r *routeRegexp) Match(req *http.Request, match *RouteMatch) bool {
	if r.regexpType == regexpTypeHost {
		host := getHost(req)
		if r.wildcardHostPort {
			// Don't be strict on the port match
			if i := strings.Index(host, ":"); i != -1 {
				host = host[:i]
			}
		}
		return r.regexp.MatchString(host)
	}

	if r.regexpType == regexpTypeQuery {
		return r.matchQueryString(req)
	}
	path := req.URL.Path
	if r.options.useEncodedPath {
		path = req.URL.EscapedPath()
	}
	return r.regexp.MatchString(path)
}

// url builds a URL part using the given values.
func (r *routeRegexp) url(values map[string]string) (string, error) {
	urlValues := make([]interface{}, len(r.varsN))
	for k, v := range r.varsN {
		value, ok := values[v]
		if !ok {
			return "", fmt.Errorf("mux: missing route variable %q", v)
		}
		if r.regexpType == regexpTypeQuery {
			value = url.QueryEscape(value)
		}
		urlValues[k] = value
	}
	rv := fmt.Sprintf(r.reverse, urlValues...)
	if !r.regexp.MatchString(rv) {
		// The URL is checked against the full regexp, instead of checking
		// individual variables. This is faster but to provide a good error
		// message, we check individual regexps if the URL doesn't match.
		for k, v := range r.varsN {
			if !r.varsR[k].MatchString(values[v]) {
				return "", fmt.Errorf(
					"mux: variable %q doesn't match, expected %q", values[v],
					r.varsR[k].String())
			}
		}
	}
	return rv, nil
}

// getURLQuery returns a single query parameter from a request URL.
// For a URL with foo=bar&baz=ding, we return only the relevant key
// value pair for the routeRegexp.
func (r *routeRegexp) getURLQuery(req *http.Request) string {
	if r.regexpType != regexpTypeQuery {
		return ""
	}
	templateKey := strings.SplitN(r.template, "=", 2)[0]
	val, ok := findFirstQueryKey(req.URL.RawQuery, templateKey)
	if ok {
		return templateKey + "=" + val
	}
	return ""
}

// findFirstQueryKey returns the same result as (*url.URL).Query()[key][0].
// If key was not found, empty string and false is returned.
func findFirstQueryKey(rawQuery, key string) (value string, ok bool) {
	query := []byte(rawQuery)
	for len(query) > 0 {
		foundKey := query
		if i := bytes.IndexAny(foundKey, "&;"); i >= 0 {
			foundKey, query = foundKey[:i], foundKey[i+1:]
		} else {
			query = query[:0]
		}
		if len(foundKey) == 0 {
			continue
		}
		var value []byte
		if i := bytes.IndexByte(foundKey, '='); i >= 0 {
			foundKey, value = foundKey[:i], foundKey[i+1:]
		}
		if len(foundKey) < len(key) {
			// Cannot possibly be key.
			continue
		}
		keyString, err := url.QueryUnescape(string(foundKey))
		if err != nil {
			continue
		}
		if keyString != key {
			continue
		}
		valueString, err := url.QueryUnescape(string(value))
		if err != nil {
			continue
		}
		return valueString, true
	}
	return "", false
}

func (r *routeRegexp) matchQueryString(req *http.Request) bool {
	return r.regexp.MatchString(r.getURLQuery(req))
}

// braceIndices returns the first level curly brace indices from a string.
// It returns an error in case of unbalanced braces.
func braceIndices(s string) ([]int, error) {
	var level, idx int
	var idxs []int
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			if level++; level == 1 {
				idx = i
			}
		case '}':
			if level--; level == 0 {
				idxs = append(idxs, idx, i+1)
			} else if level < 0 {
				return nil, fmt.Errorf("mux: unbalanced braces in %q", s)
			}
		}
	}
	if level != 0 {
		return nil, fmt.Errorf("mux: unbalanced braces in %q", s)
	}
	return idxs, nil
}

// varGroupName builds a capturing group name for the indexed variable.
func varGroupName(idx int) string {
	return "v" + strconv.Itoa(idx)
}

// ----------------------------------------------------------------------------
// routeRegexpGroup
// ----------------------------------------------------------------------------

// routeRegexpGroup groups the route matchers that carry variables.
type routeRegexpGroup struct {
	host    *routeRegexp
	path    *routeRegexp
	queries []*routeRegexp
}

// setMatch extracts the variables from the URL once a route matches.
func (v routeRegexpGroup) setMatch(req *http.Request, m *RouteMatch, r *Route) {
	// Store host variables.
	if v.host != nil {
		host := getHost(req)
		if v.host.wildcardHostPort {
			// Don't be strict on the port match
			if i := strings.Index(host, ":"); i != -1 {
				host = host[:i]
			}
		}
		matches := v.host.regexp.FindStringSubmatchIndex(host)
		if len(matches) > 0 {
			extractVars(host, matches, v.host.varsN, m.Vars)
		}
	}
	path := req.URL.Path
	if r.useEncodedPath {
		path = req.URL.EscapedPath()
	}
	// Store path variables.
	if v.path != nil {
		matches := v.path.regexp.FindStringSubmatchIndex(path)
		if len(matches) > 0 {
			extractVars(path, matches, v.path.varsN, m.Vars)
			// Check if we should redirect.
			if v.path.options.strictSlash {
				p1 := strings.HasSuffix(path, "/")
				p2 := strings.HasSuffix(v.path.template, "/")
				if p1 != p2 {
					u, _ := url.Parse(req.URL.String())
					if p1 {
						u.Path = u.Path[:len(u.Path)-1]
					} else {
						u.Path += "/"
					}
					m.Handler = http.RedirectHandler(u.String(), http.StatusMovedPermanently)
				}
			}
		}
	}
	// Store query string variables.
	for _, q := range v.queries {
		queryURL := q.getURLQuery(req)
		matches := q.regexp.FindStringSubmatchIndex(queryURL)
		if len(matches) > 0 {
			extractVars(queryURL, matches, q.varsN, m.Vars)
		}
	}
}

// getHost tries its best to return the request host.
// According to section 14.23 of RFC 2616 the Host header
// can include the port number if the default value of 80 is not used.
func getHost(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.Host
	}
	return r.Host
}

func extractVars(input string, matches []int, names []string, output map[string]string) {
	for i, name := range names {
		output[name] = input[matches[2*i+2]:matches[2*i+3]]
	}
}

//----------------------------------------------------------------------------------------------------

// Route stores information to match a request and build URLs.
type Route struct {
	// Request handler for the route.
	handler http.Handler
	// If true, this route never matches: it is only used to build URLs.
	buildOnly bool
	// The name used to build URLs.
	name string
	// Error resulted from building a route.
	err error

	// "global" reference to all named routes
	namedRoutes map[string]*Route

	// config possibly passed in from `Router`
	routeConf
}

// SkipClean reports whether path cleaning is enabled for this route via
// Router.SkipClean.
func (r *Route) SkipClean() bool {
	return r.skipClean
}

// Match matches the route against the request.
func (r *Route) Match(req *http.Request, match *RouteMatch) bool {
	if r.buildOnly || r.err != nil {
		return false
	}

	var matchErr error

	// Match everything.
	for _, m := range r.matchers {
		if matched := m.Match(req, match); !matched {
			if _, ok := m.(methodMatcher); ok {
				matchErr = ErrMethodMismatch
				continue
			}

			// Ignore ErrNotFound errors. These errors arise from match call
			// to Subrouters.
			//
			// This prevents subsequent matching subrouters from failing to
			// run middleware. If not ignored, the middleware would see a
			// non-nil MatchErr and be skipped, even when there was a
			// matching route.
			if match.MatchErr == ErrNotFound {
				match.MatchErr = nil
			}

			matchErr = nil // nolint:ineffassign
			return false
		} else {
			// Multiple routes may share the same path but use different HTTP methods. For instance:
			// Route 1: POST "/users/{id}".
			// Route 2: GET "/users/{id}", parameters: "id": "[0-9]+".
			//
			// The router must handle these cases correctly. For a GET request to "/users/abc" with "id" as "-2",
			// The router should return a "Not Found" error as no route fully matches this request.
			if match.MatchErr == ErrMethodMismatch {
				match.MatchErr = nil
			}
		}
	}

	if matchErr != nil {
		match.MatchErr = matchErr
		return false
	}

	if match.MatchErr == ErrMethodMismatch && r.handler != nil {
		// We found a route which matches request method, clear MatchErr
		match.MatchErr = nil
		// Then override the mis-matched handler
		match.Handler = r.handler
	}

	// Yay, we have a match. Let's collect some info about it.
	if match.Route == nil {
		match.Route = r
	}
	if match.Handler == nil {
		match.Handler = r.handler
	}
	if match.Vars == nil {
		match.Vars = make(map[string]string)
	}

	// Set variables.
	r.regexp.setMatch(req, match, r)
	return true
}

// ----------------------------------------------------------------------------
// Route attributes
// ----------------------------------------------------------------------------

// GetError returns an error resulted from building the route, if any.
func (r *Route) GetError() error {
	return r.err
}

// BuildOnly sets the route to never match: it is only used to build URLs.
func (r *Route) BuildOnly() *Route {
	r.buildOnly = true
	return r
}

// Handler --------------------------------------------------------------------

// Handler sets a handler for the route.
func (r *Route) Handler(handler http.Handler) *Route {
	if r.err == nil {
		r.handler = handler
	}
	return r
}

// HandlerFunc sets a handler function for the route.
func (r *Route) HandlerFunc(f func(http.ResponseWriter, *http.Request)) *Route {
	return r.Handler(http.HandlerFunc(f))
}

// GetHandler returns the handler for the route, if any.
func (r *Route) GetHandler() http.Handler {
	return r.handler
}

// Name -----------------------------------------------------------------------

// Name sets the name for the route, used to build URLs.
// It is an error to call Name more than once on a route.
func (r *Route) Name(name string) *Route {
	if r.name != "" {
		r.err = fmt.Errorf("mux: route already has name %q, can't set %q",
			r.name, name)
	}
	if r.err == nil {
		r.name = name
		r.namedRoutes[name] = r
	}
	return r
}

// GetName returns the name for the route, if any.
func (r *Route) GetName() string {
	return r.name
}

// ----------------------------------------------------------------------------
// Matchers
// ----------------------------------------------------------------------------

// matcher types try to match a request.
type matcher interface {
	Match(*http.Request, *RouteMatch) bool
}

// addMatcher adds a matcher to the route.
func (r *Route) addMatcher(m matcher) *Route {
	if r.err == nil {
		r.matchers = append(r.matchers, m)
	}
	return r
}

// addRegexpMatcher adds a host or path matcher and builder to a route.
func (r *Route) addRegexpMatcher(tpl string, typ regexpType) error {
	if r.err != nil {
		return r.err
	}
	if typ == regexpTypePath || typ == regexpTypePrefix {
		if len(tpl) > 0 && tpl[0] != '/' {
			return fmt.Errorf("mux: path must start with a slash, got %q", tpl)
		}
		if r.regexp.path != nil {
			tpl = strings.TrimRight(r.regexp.path.template, "/") + tpl
		}
	}
	rr, err := newRouteRegexp(tpl, typ, routeRegexpOptions{
		strictSlash:    r.strictSlash,
		useEncodedPath: r.useEncodedPath,
	})
	if err != nil {
		return err
	}
	for _, q := range r.regexp.queries {
		if err = uniqueVars(rr.varsN, q.varsN); err != nil {
			return err
		}
	}
	if typ == regexpTypeHost {
		if r.regexp.path != nil {
			if err = uniqueVars(rr.varsN, r.regexp.path.varsN); err != nil {
				return err
			}
		}
		r.regexp.host = rr
	} else {
		if r.regexp.host != nil {
			if err = uniqueVars(rr.varsN, r.regexp.host.varsN); err != nil {
				return err
			}
		}
		if typ == regexpTypeQuery {
			r.regexp.queries = append(r.regexp.queries, rr)
		} else {
			r.regexp.path = rr
		}
	}
	r.addMatcher(rr)
	return nil
}

// Headers --------------------------------------------------------------------

// headerMatcher matches the request against header values.
type headerMatcher map[string]string

func (m headerMatcher) Match(r *http.Request, match *RouteMatch) bool {
	return matchMapWithString(m, r.Header, true)
}

// Headers adds a matcher for request header values.
// It accepts a sequence of key/value pairs to be matched. For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.Headers("Content-Type", "application/json",
//	          "X-Requested-With", "XMLHttpRequest")
//
// The above route will only match if both request header values match.
// If the value is an empty string, it will match any value if the key is set.
func (r *Route) Headers(pairs ...string) *Route {
	if r.err == nil {
		var headers map[string]string
		headers, r.err = mapFromPairsToString(pairs...)
		return r.addMatcher(headerMatcher(headers))
	}
	return r
}

// headerRegexMatcher matches the request against the route given a regex for the header
type headerRegexMatcher map[string]*regexp.Regexp

func (m headerRegexMatcher) Match(r *http.Request, match *RouteMatch) bool {
	return matchMapWithRegex(m, r.Header, true)
}

// HeadersRegexp accepts a sequence of key/value pairs, where the value has regex
// support. For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.HeadersRegexp("Content-Type", "application/(text|json)",
//	          "X-Requested-With", "XMLHttpRequest")
//
// The above route will only match if both the request header matches both regular expressions.
// If the value is an empty string, it will match any value if the key is set.
// Use the start and end of string anchors (^ and $) to match an exact value.
func (r *Route) HeadersRegexp(pairs ...string) *Route {
	if r.err == nil {
		var headers map[string]*regexp.Regexp
		headers, r.err = mapFromPairsToRegex(pairs...)
		return r.addMatcher(headerRegexMatcher(headers))
	}
	return r
}

// Host -----------------------------------------------------------------------

// Host adds a matcher for the URL host.
// It accepts a template with zero or more URL variables enclosed by {}.
// Variables can define an optional regexp pattern to be matched:
//
// - {name} matches anything until the next dot.
//
// - {name:pattern} matches the given regexp pattern.
//
// For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.Host("www.example.com")
//	r.Host("{subdomain}.domain.com")
//	r.Host("{subdomain:[a-z]+}.domain.com")
//
// Variable names must be unique in a given route. They can be retrieved
// calling mux.Vars(request).
func (r *Route) Host(tpl string) *Route {
	r.err = r.addRegexpMatcher(tpl, regexpTypeHost)
	return r
}

// MatcherFunc ----------------------------------------------------------------

// MatcherFunc is the function signature used by custom matchers.
type MatcherFunc func(*http.Request, *RouteMatch) bool

// Match returns the match for a given request.
func (m MatcherFunc) Match(r *http.Request, match *RouteMatch) bool {
	return m(r, match)
}

// MatcherFunc adds a custom function to be used as request matcher.
func (r *Route) MatcherFunc(f MatcherFunc) *Route {
	return r.addMatcher(f)
}

// Methods --------------------------------------------------------------------

// methodMatcher matches the request against HTTP methods.
type methodMatcher []string

func (m methodMatcher) Match(r *http.Request, match *RouteMatch) bool {
	return matchInArray(m, r.Method)
}

// Methods adds a matcher for HTTP methods.
// It accepts a sequence of one or more methods to be matched, e.g.:
// "GET", "POST", "PUT".
func (r *Route) Methods(methods ...string) *Route {
	for k, v := range methods {
		methods[k] = strings.ToUpper(v)
	}
	return r.addMatcher(methodMatcher(methods))
}

// Path -----------------------------------------------------------------------

// Path adds a matcher for the URL path.
// It accepts a template with zero or more URL variables enclosed by {}. The
// template must start with a "/".
// Variables can define an optional regexp pattern to be matched:
//
// - {name} matches anything until the next slash.
//
// - {name:pattern} matches the given regexp pattern.
//
// For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.Path("/products/").Handler(ProductsHandler)
//	r.Path("/products/{key}").Handler(ProductsHandler)
//	r.Path("/articles/{category}/{id:[0-9]+}").
//	  Handler(ArticleHandler)
//
// Variable names must be unique in a given route. They can be retrieved
// calling mux.Vars(request).
func (r *Route) Path(tpl string) *Route {
	r.err = r.addRegexpMatcher(tpl, regexpTypePath)
	return r
}

// PathPrefix -----------------------------------------------------------------

// PathPrefix adds a matcher for the URL path prefix. This matches if the given
// template is a prefix of the full URL path. See Route.Path() for details on
// the tpl argument.
//
// Note that it does not treat slashes specially ("/foobar/" will be matched by
// the prefix "/foo") so you may want to use a trailing slash here.
//
// Also note that the setting of Router.StrictSlash() has no effect on routes
// with a PathPrefix matcher.
func (r *Route) PathPrefix(tpl string) *Route {
	r.err = r.addRegexpMatcher(tpl, regexpTypePrefix)
	return r
}

// Query ----------------------------------------------------------------------

// Queries adds a matcher for URL query values.
// It accepts a sequence of key/value pairs. Values may define variables.
// For example:
//
//	r := mux.NewRouter().NewRoute()
//	r.Queries("foo", "bar", "id", "{id:[0-9]+}")
//
// The above route will only match if the URL contains the defined queries
// values, e.g.: ?foo=bar&id=42.
//
// If the value is an empty string, it will match any value if the key is set.
//
// Variables can define an optional regexp pattern to be matched:
//
// - {name} matches anything until the next slash.
//
// - {name:pattern} matches the given regexp pattern.
func (r *Route) Queries(pairs ...string) *Route {
	length := len(pairs)
	if length%2 != 0 {
		r.err = fmt.Errorf(
			"mux: number of parameters must be multiple of 2, got %v", pairs)
		return nil
	}
	for i := 0; i < length; i += 2 {
		if r.err = r.addRegexpMatcher(pairs[i]+"="+pairs[i+1], regexpTypeQuery); r.err != nil {
			return r
		}
	}

	return r
}

// Schemes --------------------------------------------------------------------

// schemeMatcher matches the request against URL schemes.
type schemeMatcher []string

func (m schemeMatcher) Match(r *http.Request, match *RouteMatch) bool {
	scheme := r.URL.Scheme
	// https://golang.org/pkg/net/http/#Request
	// "For [most] server requests, fields other than Path and RawQuery will be
	// empty."
	// Since we're an http muxer, the scheme is either going to be http or https
	// though, so we can just set it based on the tls termination state.
	if scheme == "" {
		if r.TLS == nil {
			scheme = "http"
		} else {
			scheme = "https"
		}
	}
	return matchInArray(m, scheme)
}

// Schemes adds a matcher for URL schemes.
// It accepts a sequence of schemes to be matched, e.g.: "http", "https".
// If the request's URL has a scheme set, it will be matched against.
// Generally, the URL scheme will only be set if a previous handler set it,
// such as the ProxyHeaders handler from gorilla/handlers.
// If unset, the scheme will be determined based on the request's TLS
// termination state.
// The first argument to Schemes will be used when constructing a route URL.
func (r *Route) Schemes(schemes ...string) *Route {
	for k, v := range schemes {
		schemes[k] = strings.ToLower(v)
	}
	if len(schemes) > 0 {
		r.buildScheme = schemes[0]
	}
	return r.addMatcher(schemeMatcher(schemes))
}

// BuildVarsFunc --------------------------------------------------------------

// BuildVarsFunc is the function signature used by custom build variable
// functions (which can modify route variables before a route's URL is built).
type BuildVarsFunc func(map[string]string) map[string]string

// BuildVarsFunc adds a custom function to be used to modify build variables
// before a route's URL is built.
func (r *Route) BuildVarsFunc(f BuildVarsFunc) *Route {
	if r.buildVarsFunc != nil {
		// compose the old and new functions
		old := r.buildVarsFunc
		r.buildVarsFunc = func(m map[string]string) map[string]string {
			return f(old(m))
		}
	} else {
		r.buildVarsFunc = f
	}
	return r
}

// Subrouter ------------------------------------------------------------------

// Subrouter creates a subrouter for the route.
//
// It will test the inner routes only if the parent route matched. For example:
//
//	r := mux.NewRouter().NewRoute()
//	s := r.Host("www.example.com").Subrouter()
//	s.HandleFunc("/products/", ProductsHandler)
//	s.HandleFunc("/products/{key}", ProductHandler)
//	s.HandleFunc("/articles/{category}/{id:[0-9]+}"), ArticleHandler)
//
// Here, the routes registered in the subrouter won't be tested if the host
// doesn't match.
func (r *Route) Subrouter() *Router {
	// initialize a subrouter with a copy of the parent route's configuration
	router := &Router{routeConf: copyRouteConf(r.routeConf), namedRoutes: r.namedRoutes}
	r.addMatcher(router)
	return router
}

// ----------------------------------------------------------------------------
// URL building
// ----------------------------------------------------------------------------

// URL builds a URL for the route.
//
// It accepts a sequence of key/value pairs for the route variables. For
// example, given this route:
//
//	r := mux.NewRouter()
//	r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).
//	  Name("article")
//
// ...a URL for it can be built using:
//
//	url, err := r.Get("article").URL("category", "technology", "id", "42")
//
// ...which will return an url.URL with the following path:
//
//	"/articles/technology/42"
//
// This also works for host variables:
//
//	r := mux.NewRouter()
//	r.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler).
//	  Host("{subdomain}.domain.com").
//	  Name("article")
//
//	// url.String() will be "http://news.domain.com/articles/technology/42"
//	url, err := r.Get("article").URL("subdomain", "news",
//	                                 "category", "technology",
//	                                 "id", "42")
//
// The scheme of the resulting url will be the first argument that was passed to Schemes:
//
//	// url.String() will be "https://example.com"
//	r := mux.NewRouter().NewRoute()
//	url, err := r.Host("example.com")
//	             .Schemes("https", "http").URL()
//
// All variables defined in the route are required, and their values must
// conform to the corresponding patterns.
func (r *Route) URL(pairs ...string) (*url.URL, error) {
	if r.err != nil {
		return nil, r.err
	}
	values, err := r.prepareVars(pairs...)
	if err != nil {
		return nil, err
	}
	var scheme, host, path string
	queries := make([]string, 0, len(r.regexp.queries))
	if r.regexp.host != nil {
		if host, err = r.regexp.host.url(values); err != nil {
			return nil, err
		}
		scheme = "http"
		if r.buildScheme != "" {
			scheme = r.buildScheme
		}
	}
	if r.regexp.path != nil {
		if path, err = r.regexp.path.url(values); err != nil {
			return nil, err
		}
	}
	for _, q := range r.regexp.queries {
		var query string
		if query, err = q.url(values); err != nil {
			return nil, err
		}
		queries = append(queries, query)
	}
	return &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     path,
		RawQuery: strings.Join(queries, "&"),
	}, nil
}

// URLHost builds the host part of the URL for a route. See Route.URL().
//
// The route must have a host defined.
func (r *Route) URLHost(pairs ...string) (*url.URL, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.regexp.host == nil {
		return nil, errors.New("mux: route doesn't have a host")
	}
	values, err := r.prepareVars(pairs...)
	if err != nil {
		return nil, err
	}
	host, err := r.regexp.host.url(values)
	if err != nil {
		return nil, err
	}
	u := &url.URL{
		Scheme: "http",
		Host:   host,
	}
	if r.buildScheme != "" {
		u.Scheme = r.buildScheme
	}
	return u, nil
}

// URLPath builds the path part of the URL for a route. See Route.URL().
//
// The route must have a path defined.
func (r *Route) URLPath(pairs ...string) (*url.URL, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.regexp.path == nil {
		return nil, errors.New("mux: route doesn't have a path")
	}
	values, err := r.prepareVars(pairs...)
	if err != nil {
		return nil, err
	}
	path, err := r.regexp.path.url(values)
	if err != nil {
		return nil, err
	}
	return &url.URL{
		Path: path,
	}, nil
}

// GetPathTemplate returns the template used to build the
// route match.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not define a path.
func (r *Route) GetPathTemplate() (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.regexp.path == nil {
		return "", errors.New("mux: route doesn't have a path")
	}
	return r.regexp.path.template, nil
}

// GetPathRegexp returns the expanded regular expression used to match route path.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not define a path.
func (r *Route) GetPathRegexp() (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.regexp.path == nil {
		return "", errors.New("mux: route does not have a path")
	}
	return r.regexp.path.regexp.String(), nil
}

// GetQueriesRegexp returns the expanded regular expressions used to match the
// route queries.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not have queries.
func (r *Route) GetQueriesRegexp() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.regexp.queries == nil {
		return nil, errors.New("mux: route doesn't have queries")
	}
	queries := make([]string, 0, len(r.regexp.queries))
	for _, query := range r.regexp.queries {
		queries = append(queries, query.regexp.String())
	}
	return queries, nil
}

// GetQueriesTemplates returns the templates used to build the
// query matching.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not define queries.
func (r *Route) GetQueriesTemplates() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	if r.regexp.queries == nil {
		return nil, errors.New("mux: route doesn't have queries")
	}
	queries := make([]string, 0, len(r.regexp.queries))
	for _, query := range r.regexp.queries {
		queries = append(queries, query.template)
	}
	return queries, nil
}

// GetMethods returns the methods the route matches against
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if route does not have methods.
func (r *Route) GetMethods() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	for _, m := range r.matchers {
		if methods, ok := m.(methodMatcher); ok {
			return []string(methods), nil
		}
	}
	return nil, errors.New("mux: route doesn't have methods")
}

// GetHostTemplate returns the template used to build the
// route match.
// This is useful for building simple REST API documentation and for instrumentation
// against third-party services.
// An error will be returned if the route does not define a host.
func (r *Route) GetHostTemplate() (string, error) {
	if r.err != nil {
		return "", r.err
	}
	if r.regexp.host == nil {
		return "", errors.New("mux: route doesn't have a host")
	}
	return r.regexp.host.template, nil
}

// GetVarNames returns the names of all variables added by regexp matchers
// These can be used to know which route variables should be passed into r.URL()
func (r *Route) GetVarNames() ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	var varNames []string
	if r.regexp.host != nil {
		varNames = append(varNames, r.regexp.host.varsN...)
	}
	if r.regexp.path != nil {
		varNames = append(varNames, r.regexp.path.varsN...)
	}
	for _, regx := range r.regexp.queries {
		varNames = append(varNames, regx.varsN...)
	}
	return varNames, nil
}

// prepareVars converts the route variable pairs into a map. If the route has a
// BuildVarsFunc, it is invoked.
func (r *Route) prepareVars(pairs ...string) (map[string]string, error) {
	m, err := mapFromPairsToString(pairs...)
	if err != nil {
		return nil, err
	}
	return r.buildVars(m), nil
}

func (r *Route) buildVars(m map[string]string) map[string]string {
	if r.buildVarsFunc != nil {
		m = r.buildVarsFunc(m)
	}
	return m
}

//----------------------------------------------------------------------------------------------------
