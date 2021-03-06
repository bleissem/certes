﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Certes.Jws;
using Certes.Pkcs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.Management.Dns.Fluent;
using Microsoft.Azure.Management.Dns.Fluent.Models;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Certes.Tests.Web
{
    public class Startup
    {
        public IConfigurationRoot Configuration { get; }

        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder();

            if (env.IsDevelopment())
            {
                builder.AddUserSecrets<Startup>();
            }

            builder.AddEnvironmentVariables();
            Configuration = builder.Build();
        }
        
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.Map("/dns-01", sub => sub.Run(Dns));
            app.Map("/.well-known/acme-challenge", sub => sub.Run(AcmeChallenge));
            app.Run(Fallback);
        }

        private async Task Dns(HttpContext context)
        {
            var request = context.Request;

            if (request.Method == "PUT")
            {
                Dictionary<string, string> tokens;
                using (var reader = new StreamReader(request.Body))
                {
                    var json = await reader.ReadToEndAsync();
                    tokens = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                }

                var path = request.Path.ToUriComponent();
                var keyType = Enum.Parse<KeyAlgorithm>(path.Substring(1), true);
                var accountKey = GetTestKey(keyType);

                var loginInfo = new ServicePrincipalLoginInformation
                {
                    ClientId = Configuration["clientId"],
                    ClientSecret = Configuration["clientSecret"],
                };

                var credentials = new AzureCredentials(loginInfo, Configuration["tenantId"], AzureEnvironment.AzureGlobalCloud);
                using (var client = new DnsManagementClient(credentials))
                {
                    client.SubscriptionId = Configuration["subscriptionId"];

                    foreach (var p in tokens)
                    {
                        var name = "_acme-challenge." + p.Key.Replace(".dymetis.com", "");
                        await client.RecordSets.CreateOrUpdateAsync(
                            "dymetis",
                            "dymetis.com",
                            name,
                            RecordType.TXT,
                            new RecordSetInner(
                                name: name,
                                tTL: 1,
                                txtRecords: new[] { new TxtRecord(new[] { accountKey.SignatureKey.DnsTxt(p.Value) }) }));
                    }
                }
            }
        }

        private async Task AcmeChallenge(HttpContext context)
        {
            var request = context.Request;
            var path = request.Path.ToUriComponent();
            if (request.Method == "GET" && path?.Length > 1 && path.StartsWith("/"))
            {
                var accountKey = GetTestKey(request);
                var token = path.Substring(1);

                context.Response.ContentType = "plain/text";
                await context.Response.WriteAsync(accountKey.KeyAuthorization(token));
            }
        }

        private async Task Fallback(HttpContext context)
        {
            await context.Response.WriteAsync("Find Certes project on GitHub - https://goo.gl/beyaxD");
        }

        private AccountKey GetTestKey(KeyAlgorithm algo)
        {
            var key =
                algo == KeyAlgorithm.ES256 ? Keys.ES256Key :
                algo == KeyAlgorithm.ES384 ? Keys.ES384Key :
                algo == KeyAlgorithm.ES512 ? Keys.ES512Key :
                Keys.RS256Key;

            using (var buffer = new MemoryStream(Encoding.UTF8.GetBytes(key)))
            {
                return new AccountKey(KeyInfo.From(buffer));
            }
        }

        private AccountKey GetTestKey(HttpRequest request)
        {
            var host = request.Host.Host;
            return
                host.IndexOf(".es256.", StringComparison.OrdinalIgnoreCase) >= 0 ? GetTestKey(KeyAlgorithm.ES256) :
                host.IndexOf(".es384.", StringComparison.OrdinalIgnoreCase) >= 0 ? GetTestKey(KeyAlgorithm.ES384) :
                host.IndexOf(".es512.", StringComparison.OrdinalIgnoreCase) >= 0 ? GetTestKey(KeyAlgorithm.ES512) :
                GetTestKey(KeyAlgorithm.RS256);
        }
    }
}
