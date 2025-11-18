using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;

public class OSINTDogManager
{
    private HttpClient _osintDogHttpClient, _osintCatHttpClient;
    private string _osintCatApiKey;

    public OSINTDogManager()
    {
        _osintDogHttpClient = new HttpClient();
        //_osintDogHttpClient.DefaultRequestHeaders.Add("X-API-Key", File.ReadAllText("API_KEY_OSINTDOG.txt"));
        _osintDogHttpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        //_osintCatApiKey = File.ReadAllText("API_KEY_OSINTCAT.txt");

        _osintCatHttpClient = new HttpClient();
        _osintCatHttpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0");
    }

    public string OsintCatLookup(string query, string searchType)
    {
        try
        {
            HttpResponseMessage response = _osintCatHttpClient.GetAsync($"https://osintcat.ru/api/{searchType}?id={_osintCatApiKey}&query={Uri.EscapeDataString(query)}").Result;
            return response.Content.ReadAsStringAsync().Result.Replace("osintcat.ru", "Crystal OSINT");
        }
        catch
        {
            return "";
        }
    }

    public string SnusbaseSearch(string query, string searchType)
    {
        // email, username, lastip, hash, password, name, _domain
        string json = "{\"terms\": [\"" + query + "\"], \"types\": [\"" + searchType + "\"], \"wildcard\": false, \"group_by\": \"db\", \"tables\": null}";
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        try
        {
            HttpResponseMessage response = _osintDogHttpClient.PostAsync("https://osintdog.com/api/snusbase/search", content).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.PostAsync("https://osintdog.com/api/leakcheck/v2", content).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.PostAsync("https://osintdog.com/api/hackcheck", content).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.PostAsync("https://osintdog.com/api/breachbase", content).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.PostAsync("https://osintdog.com/api/intelvault", content).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.GetAsync("https://osintdog.com/api/inf0sec/" + searchType + "?q=" + Uri.EscapeDataString(query)).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.PostAsync("https://osintdog.com/api/akula", content).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.PostAsync("https://osintdog.com/api/leaksight", content).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.GetAsync("https://osintdog.com/api/oathnet/holehe?email=" + Uri.EscapeDataString(query)).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.GetAsync("https://osintdog.com/api/oathnet/ghunt?email=" + Uri.EscapeDataString(query)).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.GetAsync("https://osintdog.com/api/seon/email?email=" + Uri.EscapeDataString(query)).Result;
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
            HttpResponseMessage response = _osintDogHttpClient.GetAsync("https://osintdog.com/api/seon/phone?phone=" + Uri.EscapeDataString(query)).Result;
            return response.Content.ReadAsStringAsync().Result;
        }
        catch
        {
            return "";
        }
    }
}