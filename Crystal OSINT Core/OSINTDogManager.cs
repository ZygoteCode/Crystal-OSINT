using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

public class OSINTDogManager
{
    private HttpClient _httpClient;

    public OSINTDogManager()
    {
        _httpClient = new HttpClient();

        _httpClient.DefaultRequestHeaders.Add("X-API-Key", File.ReadAllText("API_KEY.txt"));
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public string SnusbaseSearch(string query, string searchType)
    {
        //  email, username, lastip, hash, password, name, _domain
        string json = "{\"terms\": [\"" + query + "\"], \"types\": [\"" + searchType + "\"], \"wildcard\": false, \"group_by\": \"db\", \"tables\": null}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = _httpClient.PostAsync("https://osintdog.com/api/snusbase/search", content).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string LeakCheckSearch(string query, string searchType)
    {
        // email, username, phone, domain, ip, auto, hash
        string json = "{\"term\": \"" + query + "\", \"search_type\": \"" + searchType + "\", \"limit\": 1000, \"offset\": 0}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = _httpClient.PostAsync("https://osintdog.com/api/leakcheck/v2", content).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string HackCheckSearch(string query, string searchType)
    {
        // email, password, username, full_name, ip_address, phone_number, hash, domain
        string json = "{\"term\": \"" + query + "\", \"search_type\": \"" + searchType + "\"}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = _httpClient.PostAsync("https://osintdog.com/api/hackcheck", content).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string BreachBaseSearch(string query, string searchType)
    {
        // email, username, lastip
        string json = "{\"term\": \"" + query + "\", \"search_type\": \"" + searchType + "\"}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = _httpClient.PostAsync("https://osintdog.com/api/breachbase", content).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string IntelVaultSearch(string query, string searchType)
    {
        // ???
        string json = "{\"field\": [{\"" + searchType + "\": \"" + query + "\"}]}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = _httpClient.PostAsync("https://osintdog.com/api/intelvault", content).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string Inf0SecSearch(string query, string searchType)
    {
        // leaks, discord, npd, domain, username, hlr, cfx
        try
        {
            HttpResponseMessage response = _httpClient.GetAsync("https://osintdog.com/api/inf0sec/" + searchType + "?q=" + Uri.EscapeDataString(query)).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }


    public string AkulaSearch(string query, string searchType)
    {
        // email, username, domain
        string json = "{\"searchTerm\": \"" + query + "\", \"search_type\": \"" + searchType + "\"}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = _httpClient.PostAsync("https://osintdog.com/api/akula", content).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string LeakSightSearch(string query, string searchType)
    {
        // username, url, number, ip, hwid, subdomains, subnet, proxydetect, portscam, name, ipgeo, cpf, urls, search_url_all_database
        string json = "{\"term\": \"" + query + "\", \"search_type\": \"" + searchType + "\"}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = _httpClient.PostAsync("https://osintdog.com/api/leaksight", content).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string OathNetHoleleEmailSearch(string query)
    {
        try
        {
            HttpResponseMessage response = _httpClient.GetAsync("https://osintdog.com/api/oathnet/holehe?email=" + Uri.EscapeDataString(query)).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string OathNetGHuntEmailSearch(string query)
    {
        try
        {
            HttpResponseMessage response = _httpClient.GetAsync("https://osintdog.com/api/oathnet/ghunt?email=" + Uri.EscapeDataString(query)).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string SEONEmailSearch(string query)
    {
        try
        {
            HttpResponseMessage response = _httpClient.GetAsync("https://osintdog.com/api/seon/email?email=" + Uri.EscapeDataString(query)).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }

    public string SEONPhoneSearch(string query)
    {
        try
        {
            HttpResponseMessage response = _httpClient.GetAsync("https://osintdog.com/api/seon/phone?phone=" + Uri.EscapeDataString(query)).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }
}