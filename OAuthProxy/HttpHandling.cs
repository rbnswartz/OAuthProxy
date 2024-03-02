using System.Collections.Generic;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace OAuthProxy;

public class HttpHandling
{
    private readonly ILogger _logger;
    private readonly IConfiguration _configuration;

    public HttpHandling(ILoggerFactory loggerFactory, IConfiguration configuration)
    {
        _logger = loggerFactory.CreateLogger<HttpHandling>();
        _configuration = configuration;
    }

    [Function("Index")]
    public HttpResponseData Index([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "index")] HttpRequestData req,
        FunctionContext executionContext)
    {
        var response = req.CreateResponse(HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "text/html; charset=utf-8");
        response.WriteString("""
                             <html>
                                <head>
                                    <title>OAuth Proxy</title>
                                </head>
                                <body>
                                    <a href="/auth" target="_self">Login</a>
                                </body>
                             </html>
                             """);
        return response;
    }
    
    [Function("Auth")]
    public HttpResponseData Auth([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "auth")] HttpRequestData req,
        FunctionContext executionContext)
    {
        var clientId = _configuration["ClientId"];
        var redirectUri = BuildLocalUrl(req, "/callback");
        var scopes = new List<string> { "user", "repo" };
        var authUrl = BuildOAuthLoginUrl(clientId, redirectUri, scopes);
        var response = req.CreateResponse(HttpStatusCode.Found);
        response.Headers.Add("Location", authUrl);
        return response;
    }
    
    [Function("Callback")]
    public async Task<HttpResponseData> Callback([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "callback")] HttpRequestData req,
        FunctionContext executionContext)
    {
        var code = req.Query["code"];
        if (string.IsNullOrEmpty(code))
        {
            var errorResponse = req.CreateResponse(HttpStatusCode.BadRequest);
            errorResponse.Headers.Add("Content-Type", "text/html; charset=utf-8");
            errorResponse.WriteString("Code is missing");
            return errorResponse;
        }
        var clientId = _configuration["ClientId"];
        var clientSecret = _configuration["ClientSecret"];
        var originPattern = _configuration["OriginPattern"];
        var redirectUri = BuildLocalUrl(req, "/callback");
        
        var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {code}");
        var tokenResponse = await httpClient.GetFromJsonAsync<TokenResponse>(BuildOAuthTokenUrl(clientId, clientSecret, code, ""));
        
        var response = req.CreateResponse(HttpStatusCode.OK);
        var dcapResponse = "{\"token\": \"" + tokenResponse.AccessToken + "\", \"provider\": \"github\"}";
        response.Headers.Add("Content-Type", "text/html; charset=utf-8");
        var template = $$"""
                       <html>
                          <head>
                              <title>OAuth Proxy</title>
                          </head>
                          <body>
                          <script>
                          (function(){
                              function receiveMessage(event){
                                  if (!event.origin.match('{{originPattern}}')){
                                     console.log('Invalid origin: ' + event.origin);
                                     return;
                                  }
                                  window.opener.postMessage('authorization:github:success:{{dcapResponse}}', event.origin);
                              }
                              window.addEventListener('message', receiveMessage, false);
                              window.opener.postMessage('authorizing:github', '*');
                          })();
                          </script>
                          </body>
                       </html>
                       """;
        response.WriteString(template);
        return response;
    }
    
    private string BuildOAuthLoginUrl(string clientId, string redirectUri, List<string> scopes)
    {
        var scope = string.Join(" ", scopes);

        var state = GetRandomString();
        
        return $"https://github.com/login/oauth/authorize?client_id={clientId}&redirect_uri={redirectUri}&scope={scope}&state={state}";
    }

    private string BuildOAuthTokenUrl(string clientId, string clientSecret, string code, string redirectUri)
    { 
        return $"http://github.com/login/oauth/access_token?client_id={clientId}&client_secret={clientSecret}&code={code}&redirect_uri={redirectUri}";
    }

    private string GetRandomString()
    {
        return Path.GetRandomFileName().Replace(".", "");
    }
    
    private string BuildLocalUrl(HttpRequestData req, string path)
    {
        return req.Url.Scheme + "://" + req.Url.Host + (req.Url.IsDefaultPort ? "" : ":" + req.Url.Port) + path;
    }
}


internal class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; }
    [JsonPropertyName("scope")]
    public string Scope { get; set; }
}
