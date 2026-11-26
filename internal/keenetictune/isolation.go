package keenetictune

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
)

type routeTarget struct {
	TunnelID  string `json:"tunnelId"`
	Interface string `json:"interface"`
	Fallback  string `json:"fallback"`
}

type dnsRoute struct {
	PolicyInterfaces []string      `json:"hrPolicyInterfaces"`
	Routes           []routeTarget `json:"routes"`
}

type accessPolicy struct {
	Held       []string `json:"held"`
	Interfaces []struct {
		Name string `json:"name"`
	} `json:"interfaces"`
}

func (r *Router) checkIsolation(ctx context.Context, t observedTunnel) error {
	if !slices.Contains(t.details.Peer.AllowedIPs, "0.0.0.0/0") {
		return errors.New("тестовый туннель должен принимать IPv4-трафик HTTP-пробы")
	}
	names := []string{t.details.InterfaceName, t.details.NDMSName, t.listed.InterfaceName, t.listed.NDMSName}
	refersToTunnel := func(v string) bool {
		if v == r.config.TunnelID || v == "tunnel:"+r.config.TunnelID {
			return true
		}
		return v != "" && slices.ContainsFunc(names, func(name string) bool {
			return strings.EqualFold(name, v)
		})
	}
	for _, other := range t.all {
		if other.ID != r.config.TunnelID && refersToTunnel(other.ISPInterface) {
			return errors.New("другой туннель использует тестовый туннель как маршрут выхода")
		}
	}

	for _, path := range []string{"/api/static-routes/list", "/api/client-routes"} {
		var routes *[]routeTarget
		if err := r.rest(ctx, path, nil, &routes); err != nil || routes == nil {
			return errors.New("AWG Manager не подтвердил отсутствие статических или клиентских маршрутов")
		}
		for _, route := range *routes {
			if refersToTunnel(route.TunnelID) || refersToTunnel(route.Interface) || refersToTunnel(route.Fallback) {
				return errors.New("тестовый туннель используется статическим или клиентским маршрутом")
			}
		}
	}

	var dnsRoutes *[]dnsRoute
	if err := r.rest(ctx, "/api/dns-routes/list", nil, &dnsRoutes); err != nil || dnsRoutes == nil {
		return errors.New("AWG Manager не подтвердил отсутствие DNS-маршрутов")
	}
	for _, route := range *dnsRoutes {
		if slices.ContainsFunc(route.PolicyInterfaces, refersToTunnel) {
			return errors.New("тестовый туннель используется политикой DNS-маршрутизации")
		}
		for _, target := range route.Routes {
			if refersToTunnel(target.TunnelID) || refersToTunnel(target.Interface) || refersToTunnel(target.Fallback) {
				return errors.New("тестовый туннель используется DNS-маршрутом")
			}
		}
	}

	var policies *[]accessPolicy
	if err := r.rest(ctx, "/api/access-policies", url.Values{"refresh": {"true"}}, &policies); err != nil || policies == nil {
		return errors.New("AWG Manager не подтвердил отсутствие политик доступа")
	}
	for _, policy := range *policies {
		if slices.ContainsFunc(policy.Held, refersToTunnel) {
			return errors.New("тестовый туннель указан в политике доступа")
		}
		for _, iface := range policy.Interfaces {
			if refersToTunnel(iface.Name) {
				return errors.New("тестовый туннель указан в политике доступа")
			}
		}
	}
	return nil
}
