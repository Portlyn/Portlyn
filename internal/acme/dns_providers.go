package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	libdnsdo "github.com/libdns/digitalocean"
	"github.com/libdns/libdns"
	libdnsroute53 "github.com/libdns/route53"

	"portlyn/internal/domain"
	"portlyn/internal/secureconfig"
)

func buildDNSProvider(secrets []string, item *domain.DNSProvider) (libdns.RecordAppender, libdns.RecordDeleter, error) {
	if item == nil {
		return nil, nil, fmt.Errorf("dns provider is required")
	}
	keySet := make([][]byte, 0, len(secrets))
	for _, secret := range secrets {
		if strings.TrimSpace(secret) != "" {
			keySet = append(keySet, []byte(secret))
		}
	}
	config, err := secureconfig.DecryptJSONAuto(keySet, item.ConfigEncrypted)
	if err != nil {
		return nil, nil, err
	}
	switch item.Type {
	case domain.DNSProviderTypeCloudflare:
		provider := &cloudflareProvider{apiToken: strings.TrimSpace(config["api_token"]), client: &http.Client{Timeout: 15 * time.Second}}
		return provider, provider, nil
	case domain.DNSProviderTypeHetzner:
		provider := &hetznerProvider{apiToken: strings.TrimSpace(config["dns_api_token"]), client: &http.Client{Timeout: 15 * time.Second}}
		return provider, provider, nil
	case domain.DNSProviderTypeRoute53:
		provider := &libdnsroute53.Provider{
			Region:          strings.TrimSpace(config["region"]),
			Profile:         strings.TrimSpace(config["profile"]),
			AccessKeyId:     strings.TrimSpace(config["access_key_id"]),
			SecretAccessKey: strings.TrimSpace(config["secret_access_key"]),
			SessionToken:    strings.TrimSpace(config["session_token"]),
			HostedZoneID:    strings.TrimSpace(config["hosted_zone_id"]),
		}
		return provider, provider, nil
	case domain.DNSProviderTypeDO:
		provider := &libdnsdo.Provider{
			APIToken: strings.TrimSpace(config["api_token"]),
		}
		return provider, provider, nil
	default:
		return nil, nil, fmt.Errorf("unsupported dns provider type %q", item.Type)
	}
}

type cloudflareProvider struct {
	apiToken string
	client   *http.Client
}

func (p *cloudflareProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		payload := map[string]any{
			"type": rr.Type,
			"name": strings.TrimSuffix(libdns.AbsoluteName(rr.Name, zone), "."),
			"ttl":  int(rr.TTL / time.Second),
		}
		if payload["ttl"].(int) <= 0 {
			payload["ttl"] = 120
		}
		if rr.Type == "TXT" {
			payload["content"] = rr.Data
		}
		var response struct {
			Success bool `json:"success"`
			Result  struct {
				Type    string `json:"type"`
				Name    string `json:"name"`
				Content string `json:"content"`
				TTL     int    `json:"ttl"`
			} `json:"result"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := p.request(ctx, http.MethodPost, "https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records", payload, &response); err != nil {
			return nil, err
		}
		if !response.Success {
			return nil, fmt.Errorf("cloudflare create record failed")
		}
		out = append(out, libdns.TXT{
			Name: libdns.RelativeName(response.Result.Name+".", zone),
			TTL:  time.Duration(response.Result.TTL) * time.Second,
			Text: response.Result.Content,
		})
	}
	return out, nil
}

func (p *cloudflareProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	deleted := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		fqdn := strings.TrimSuffix(libdns.AbsoluteName(rr.Name, zone), ".")
		recordID, lookupErr := p.lookupRecordID(ctx, zoneID, fqdn, rr.Type, rr.Data)
		if lookupErr != nil {
			return nil, lookupErr
		}
		if recordID == "" {
			continue
		}
		if err := p.request(ctx, http.MethodDelete, "https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records/"+recordID, nil, nil); err != nil {
			return nil, err
		}
		deleted = append(deleted, rec)
	}
	return deleted, nil
}

func (p *cloudflareProvider) zoneID(ctx context.Context, zone string) (string, error) {
	var response struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	query := url.Values{}
	query.Set("name", strings.TrimSuffix(zone, "."))
	if err := p.request(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/zones?"+query.Encode(), nil, &response); err != nil {
		return "", err
	}
	if !response.Success || len(response.Result) == 0 {
		return "", fmt.Errorf("cloudflare zone %q not found", zone)
	}
	return response.Result[0].ID, nil
}

func (p *cloudflareProvider) lookupRecordID(ctx context.Context, zoneID, fqdn, recordType, content string) (string, error) {
	var response struct {
		Success bool `json:"success"`
		Result  []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"result"`
	}
	query := url.Values{}
	query.Set("type", recordType)
	query.Set("name", fqdn)
	if err := p.request(ctx, http.MethodGet, "https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records?"+query.Encode(), nil, &response); err != nil {
		return "", err
	}
	for _, item := range response.Result {
		if item.Type == recordType && item.Name == fqdn && item.Content == content {
			return item.ID, nil
		}
	}
	return "", nil
}

func (p *cloudflareProvider) request(ctx context.Context, method, endpoint string, body any, out any) error {
	var payload io.Reader
	if body != nil {
		bytesBody, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(bytesBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.apiToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cloudflare api error: %s", strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type hetznerProvider struct {
	apiToken string
	client   *http.Client
}

func (p *hetznerProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		payload := map[string]any{
			"value":   rr.Data,
			"type":    rr.Type,
			"name":    rr.Name,
			"zone_id": zoneID,
			"ttl":     int(rr.TTL / time.Second),
		}
		if payload["ttl"].(int) <= 0 {
			payload["ttl"] = 120
		}
		var response struct {
			Record struct {
				Name  string `json:"name"`
				Type  string `json:"type"`
				Value string `json:"value"`
				TTL   int    `json:"ttl"`
			} `json:"record"`
		}
		if err := p.request(ctx, http.MethodPost, "https://dns.hetzner.com/api/v1/records", payload, &response); err != nil {
			return nil, err
		}
		out = append(out, libdns.TXT{
			Name: response.Record.Name,
			TTL:  time.Duration(response.Record.TTL) * time.Second,
			Text: response.Record.Value,
		})
	}
	return out, nil
}

func (p *hetznerProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.zoneID(ctx, zone)
	if err != nil {
		return nil, err
	}
	records, err := p.records(ctx, zoneID)
	if err != nil {
		return nil, err
	}
	deleted := make([]libdns.Record, 0, len(recs))
	for _, rec := range recs {
		rr := rec.RR()
		for _, existing := range records {
			if existing.Name == rr.Name && existing.Type == rr.Type && existing.Value == rr.Data {
				if err := p.request(ctx, http.MethodDelete, "https://dns.hetzner.com/api/v1/records/"+existing.ID, nil, nil); err != nil {
					return nil, err
				}
				deleted = append(deleted, rec)
				break
			}
		}
	}
	return deleted, nil
}

func (p *hetznerProvider) zoneID(ctx context.Context, zone string) (string, error) {
	var response struct {
		Zones []struct {
			ID string `json:"id"`
		} `json:"zones"`
	}
	query := url.Values{}
	query.Set("name", strings.TrimSuffix(zone, "."))
	if err := p.request(ctx, http.MethodGet, "https://dns.hetzner.com/api/v1/zones?"+query.Encode(), nil, &response); err != nil {
		return "", err
	}
	if len(response.Zones) == 0 {
		return "", fmt.Errorf("hetzner zone %q not found", zone)
	}
	return response.Zones[0].ID, nil
}

func (p *hetznerProvider) records(ctx context.Context, zoneID string) ([]struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}, error) {
	var response struct {
		Records []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"records"`
	}
	query := url.Values{}
	query.Set("zone_id", zoneID)
	if err := p.request(ctx, http.MethodGet, "https://dns.hetzner.com/api/v1/records?"+query.Encode(), nil, &response); err != nil {
		return nil, err
	}
	return response.Records, nil
}

func (p *hetznerProvider) request(ctx context.Context, method, endpoint string, body any, out any) error {
	var payload io.Reader
	if body != nil {
		bytesBody, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(bytesBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, payload)
	if err != nil {
		return err
	}
	req.Header.Set("Auth-API-Token", p.apiToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hetzner api error: %s", strings.TrimSpace(string(raw)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
