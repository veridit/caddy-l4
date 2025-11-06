package layer4

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("layer4", parseLayer4)
}

// parseLayer4 sets up the App from Caddyfile tokens. Syntax:
//
//	{
//		layer4 {
//			# srv0
//			<addresses...> {
//				...
//			}
//			# srv1
//			<addresses...> {
//				...
//			}
//		}
//	}
func parseLayer4(d *caddyfile.Dispenser, existingVal any) (any, error) {
	// an existingVal is a []httpcaddyfile.App
	apps, _ := existingVal.([]httpcaddyfile.App)

	// get or create layer4 app value
	var l4App *App
	appJSON, found := getApp(apps, "layer4")
	if found {
		err := json.Unmarshal(appJSON, &l4App)
		if err != nil {
			return nil, d.Errf("decoding existing layer4 app config: %v", err)
		}
	} else {
		l4App = &App{Servers: make(map[string]*Server)}
	}

	// get or create tls app value
	var tlsApp caddytls.TLS
	appJSON, found = getApp(apps, "tls")
	if found {
		err := json.Unmarshal(appJSON, &tlsApp)
		if err != nil {
			return nil, d.Errf("decoding existing tls app config: %v", err)
		}
	}

	d.Next() // consume wrapper name

	// No same-line options are supported
	if d.CountRemainingArgs() > 0 {
		return nil, d.ArgErr()
	}

	i := len(l4App.Servers)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		server := &Server{}
		var inst any = server
		unm, ok := inst.(caddyfile.Unmarshaler)
		if !ok {
			return nil, d.Errf("%T is not a Caddyfile unmarshaler", inst)
		}
		if err := unm.UnmarshalCaddyfile(d); err != nil {
			return nil, err
		}
		l4App.Servers["srv"+strconv.Itoa(i)] = server
		i++

		// if the server has a TLS handler with automation subjects,
		// configure the main TLS app accordingly
		if server.tlsHandlerModule != nil {
			if h, ok := server.tlsHandlerModule.(AutomationSubjectsProvider); ok {
				var subjects []string
				isInternal := false
				for _, arg := range h.AutomationSubjects() {
					if arg == "internal" {
						isInternal = true
					} else {
						subjects = append(subjects, arg)
					}
				}

				if len(subjects) > 0 && !isInternal {
					// add subjects to automate loader
					if tlsApp.CertificatesRaw == nil {
						tlsApp.CertificatesRaw = make(caddy.ModuleMap)
					}
					var automateLoader caddytls.AutomateLoader
					if tlsApp.CertificatesRaw["automate"] != nil {
						err := json.Unmarshal(tlsApp.CertificatesRaw["automate"], &automateLoader)
						if err != nil {
							return nil, fmt.Errorf("unmarshaling existing 'automate' certificate loader: %v", err)
						}
					}
					automateLoader = append(automateLoader, subjects...)
					automateBytes, err := json.Marshal(automateLoader)
					if err != nil {
						return nil, fmt.Errorf("marshaling 'automate' certificate loader: %v", err)
					}
					tlsApp.CertificatesRaw["automate"] = automateBytes
				}

				if isInternal {
					if tlsApp.Automation == nil {
						tlsApp.Automation = new(caddytls.AutomationConfig)
					}
					policy := &caddytls.AutomationPolicy{
						SubjectsRaw: subjects,
						IssuersRaw:  []json.RawMessage{json.RawMessage(`{"module":"internal"}`)},
					}
					tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, policy)
				}
			}
		}
	}

	setApp(&apps, "layer4", caddyconfig.JSON(l4App, nil))
	setApp(&apps, "tls", caddyconfig.JSON(tlsApp, nil))

	return apps, nil
}

// ParseCaddyfileNestedRoutes parses the Caddyfile tokens for nested named matcher sets, handlers and matching timeout,
// composes a list of route configurations, and adjusts the matching timeout.
func ParseCaddyfileNestedRoutes(d *caddyfile.Dispenser, routes *RouteList, matchingTimeout *caddy.Duration, tlsHandlerModule *any) error {
	var hasMatchingTimeout bool
	var hasTLS bool
	matcherSetTokensByName, routeTokens := make(map[string][]caddyfile.Token), make([]caddyfile.Token, 0)
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		optionName := d.Val()
		if len(optionName) > 1 && optionName[0] == '@' {
			if _, exists := matcherSetTokensByName[optionName]; exists {
				return d.Errf("duplicate matcher set '%s'", d.Val())
			}
			matcherSetTokensByName[optionName] = append(matcherSetTokensByName[optionName], d.NextSegment()...)
		} else if optionName == "matching_timeout" {
			if hasMatchingTimeout {
				return d.Errf("duplicate option '%s'", optionName)
			}
			if d.CountRemainingArgs() > 1 || !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("parsing option '%s' duration: %v", optionName, err)
			}
			*matchingTimeout, hasMatchingTimeout = caddy.Duration(dur), true
		} else if optionName == "route" {
			routeTokens = append(routeTokens, d.NextSegment()...)
		} else if optionName == "tls" {
			if hasTLS {
				return d.Err("tls block already specified")
			}
			mod, err := caddyfile.UnmarshalModule(d.NewFromNextSegment(), "layer4.handlers.tls")
			if err != nil {
				return err
			}
			*tlsHandlerModule = mod
			hasTLS = true
		} else {
			return d.ArgErr()
		}
	}

	matcherSetsByName := make(map[string]caddy.ModuleMap)
	for matcherSetName, tokens := range matcherSetTokensByName {
		dd := caddyfile.NewDispenser(tokens)
		dd.Next() // consume wrapper name
		if !dd.NextArg() && !dd.NextBlock(dd.Nesting()) {
			return dd.ArgErr()
		}

		dd.Reset() // reset dispenser after argument/block checks above
		dd.Next()  // consume wrapper name again
		matcherSet, err := ParseCaddyfileNestedMatcherSet(dd)
		if err != nil {
			return err
		}
		matcherSetsByName[matcherSetName] = matcherSet
	}

	dd := caddyfile.NewDispenser(routeTokens)
	for dd.Next() { // consume route wrapper name
		route := Route{}

		if dd.CountRemainingArgs() > 0 {
			for dd.NextArg() {
				matcherSetName := dd.Val()
				matcherSet, exists := matcherSetsByName[matcherSetName]
				if !exists {
					return dd.Errf("undefined matcher set '%s'", matcherSetName)
				}
				route.MatcherSetsRaw = append(route.MatcherSetsRaw, matcherSet)
			}
		}

		if err := ParseCaddyfileNestedHandlers(dd, &route.HandlersRaw); err != nil {
			return err
		}
		*routes = append(*routes, &route)
	}

	return nil
}

// ParseCaddyfileNestedHandlers parses the Caddyfile tokens for nested handlers,
// and composes a list of their raw json configurations.
func ParseCaddyfileNestedHandlers(d *caddyfile.Dispenser, handlersRaw *[]json.RawMessage) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		handlerName := d.Val()

		unm, err := caddyfile.UnmarshalModule(d, "layer4.handlers."+handlerName)
		if err != nil {
			return err
		}
		nh, ok := unm.(NextHandler)
		if !ok {
			return d.Errf("handler module '%s' is not a layer4 connection handler", handlerName)
		}
		handlerConfig := caddyconfig.JSON(nh, nil)

		handlerConfig, err = SetModuleNameInline("handler", handlerName, handlerConfig)
		if err != nil {
			return err
		}
		*handlersRaw = append(*handlersRaw, handlerConfig)
	}

	return nil
}

// ParseCaddyfileNestedMatcherSet parses the Caddyfile tokens for a nested matcher set,
// and returns its raw module map value.
func ParseCaddyfileNestedMatcherSet(d *caddyfile.Dispenser) (caddy.ModuleMap, error) {
	matcherMap := make(map[string]ConnMatcher)

	tokensByMatcherName := make(map[string][]caddyfile.Token)
	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		matcherName := d.Val()
		if _, exists := tokensByMatcherName[matcherName]; exists {
			return nil, d.Errf("duplicate matcher module '%s'", matcherName)
		}
		tokensByMatcherName[matcherName] = append(tokensByMatcherName[matcherName], d.NextSegment()...)
	}

	for matcherName, tokens := range tokensByMatcherName {
		dd := caddyfile.NewDispenser(tokens)
		dd.Next() // consume wrapper name

		unm, err := caddyfile.UnmarshalModule(dd, "layer4.matchers."+matcherName)
		if err != nil {
			return nil, err
		}
		cm, ok := unm.(ConnMatcher)
		if !ok {
			return nil, d.Errf("matcher module '%s' is not a layer4 connection matcher", matcherName)
		}
		matcherMap[matcherName] = cm
	}

	matcherSet := make(caddy.ModuleMap)
	for name, matcher := range matcherMap {
		jsonBytes, err := json.Marshal(matcher)
		if err != nil {
			return nil, d.Errf("marshaling %T matcher: %v", matcher, err)
		}
		matcherSet[name] = jsonBytes
	}

	return matcherSet, nil
}

// ParseCaddyfileNestedTLSMatcherSet parses the Caddyfile tokens for a nested
// TLS handshake matcher set, and returns its raw module map value.
func ParseCaddyfileNestedTLSMatcherSet(d *caddyfile.Dispenser) (caddy.ModuleMap, error) {
	matcherMap := make(map[string]caddytls.ConnectionMatcher)

	tokensByMatcherName := make(map[string][]caddyfile.Token)
	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		matcherName := d.Val()
		tokensByMatcherName[matcherName] = append(tokensByMatcherName[matcherName], d.NextSegment()...)
	}

	for matcherName, tokens := range tokensByMatcherName {
		dd := caddyfile.NewDispenser(tokens)
		dd.Next() // consume wrapper name

		unm, err := caddyfile.UnmarshalModule(dd, "tls.handshake_match."+matcherName)
		if err != nil {
			return nil, err
		}
		cm, ok := unm.(caddytls.ConnectionMatcher)
		if !ok {
			return nil, fmt.Errorf("matcher module '%s' is not a connection matcher", matcherName)
		}
		matcherMap[matcherName] = cm
	}

	matcherSet := make(caddy.ModuleMap)
	for name, matcher := range matcherMap {
		jsonBytes, err := json.Marshal(matcher)
		if err != nil {
			return nil, fmt.Errorf("marshaling %T matcher: %v", matcher, err)
		}
		matcherSet[name] = jsonBytes
	}

	return matcherSet, nil
}

// SetModuleNameInline sets the string value of moduleNameKey to moduleName in raw,
// where raw must be a JSON encoding of a map, and returns the modified raw.
// In fact, it is a reverse function for caddy.getModuleNameInline.
func SetModuleNameInline(moduleNameKey, moduleName string, raw json.RawMessage) (json.RawMessage, error) {
	// temporarily unmarshal json into a map of string to any
	var tmp map[string]any
	err := json.Unmarshal(raw, &tmp)
	if err != nil {
		return nil, err
	}

	// add an inline key with the module name
	tmp[moduleNameKey] = moduleName

	// re-marshal the map into json
	result, err := json.Marshal(tmp)
	if err != nil {
		return nil, fmt.Errorf("re-encoding module '%s' configuration: %v", moduleName, err)
	}

	return result, nil
}

func getApp(apps []httpcaddyfile.App, name string) (json.RawMessage, bool) {
	for _, app := range apps {
		if app.Name == name {
			return app.Value, true
		}
	}
	return nil, false
}

func setApp(apps *[]httpcaddyfile.App, name string, value json.RawMessage) {
	for i, app := range *apps {
		if app.Name == name {
			(*apps)[i].Value = value
			return
		}
	}
	*apps = append(*apps, httpcaddyfile.App{Name: name, Value: value})
}
