using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Secrets;
using Azure.Identity;

namespace GetAccessTokenDemo
{
    public class MyHttpTrigger
    {
        private readonly ILogger<MyHttpTrigger> _logger;

        public MyHttpTrigger(ILogger<MyHttpTrigger> logger)
        {
            _logger = logger;
        }

        [Function("MyHttpTrigger")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");

            string KeyVaultURI = "<Key Vault URI>";
            string certificateName = "<Certificate Name>";

            SecretClient kvClient = new SecretClient(new Uri(KeyVaultURI), new DefaultAzureCredential());
            KeyVaultSecret secret = await kvClient.GetSecretAsync(certificateName);

            string clientId = "<Client ID>";
            string tenantId = "<Tenant ID>";
            
            string authority = $"https://login.microsoftonline.com/{tenantId}";
            string scope = "https://graph.microsoft.com/.default";
            
            byte[] certificateByte =  Convert.FromBase64String(secret.Value);
            X509Certificate2 certificate = new X509Certificate2(certificateByte,
            string.Empty, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

            IConfidentialClientApplication app = ConfidentialClientApplicationBuilder.Create(clientId)                
                .WithCertificate(certificate)
                .WithAuthority(authority)
                .Build();

            var authResult = await app.AcquireTokenForClient(new[] { scope })
                                .ExecuteAsync()
                                .ConfigureAwait(false);

            return new OkObjectResult(authResult.AccessToken);
        }
    }
}
