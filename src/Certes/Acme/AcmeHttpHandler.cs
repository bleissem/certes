﻿using Certes.Json;
using Certes.Jws;
using Certes.Pkcs;
using Newtonsoft.Json;
using System;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Certes.Acme
{
    /// <summary>
    /// Represents the HTTP handler for communicating with ACME server.
    /// </summary>
    /// <seealso cref="System.IDisposable" />
    public class AcmeHttpHandler : IAcmeHttpHandler, IDisposable
    {
        private const string MimeJson = "application/json";
        private static Lazy<HttpClient> SharedHttp = new Lazy<HttpClient>(() => new HttpClient());

        private readonly HttpClient http;
        private readonly Uri serverUri;

        private string nextNonce;
        private Resource.Directory directory;

        private readonly bool shouldDisposeHander;

        private readonly JsonSerializerSettings jsonSettings = JsonUtil.CreateSettings();

        /// <summary>
        /// Gets the ACME server URI.
        /// </summary>
        /// <value>
        /// The ACME server URI.
        /// </value>
        public Uri ServerUri
        {
            get
            {
                return serverUri;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeHttpHandler"/> class.
        /// </summary>
        /// <param name="serverUri">The server URI.</param>
        public AcmeHttpHandler(Uri serverUri) : this(serverUri, SharedHttp.Value)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeHttpHandler"/> class.
        /// </summary>
        /// <param name="serverUri">The server URI.</param>
        /// <param name="httpMessageHandler">The HTTP message handler.</param>
        [Obsolete("Use AcmeHttpHandler(Uri, HttpClient) instead for reusing HttpClient.")]
        public AcmeHttpHandler(Uri serverUri, HttpMessageHandler httpMessageHandler = null)
        {
            if (httpMessageHandler == null)
            {
                this.http = SharedHttp.Value;
            }
            else
            {
                this.http = new HttpClient(httpMessageHandler);
                this.shouldDisposeHander = true;
            }
            
            this.serverUri = serverUri;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeHttpHandler"/> class.
        /// </summary>
        /// <param name="serverUri">The server URI.</param>
        /// <param name="http">The HTTP client.</param>
        public AcmeHttpHandler(Uri serverUri, HttpClient http = null)
        {
            this.http = http ?? SharedHttp.Value;
            this.serverUri = serverUri;
        }

        /// <summary>
        /// Gets the ACME resource URI.
        /// </summary>
        /// <param name="resourceType">Type of the ACME resource.</param>
        /// <returns>The ACME resource URI</returns>
        public async Task<Uri> GetResourceUri(string resourceType)
        {
            await FetchDirectory(false);
            var resourceUri =
                ResourceTypes.NewRegistration == resourceType ? this.directory.NewReg :
                ResourceTypes.NewAuthorization == resourceType ? this.directory.NewAuthz :
                ResourceTypes.NewCertificate == resourceType ? this.directory.NewCert :
                ResourceTypes.RevokeCertificate == resourceType ? this.directory.RevokeCert :
                null;

            if (resourceUri == null)
            {
                throw new Exception($"Unsupported resource type '{resourceType}'.");
            }

            return resourceUri;
        }

        /// <summary>
        /// Performs HTTP GET to <paramref name="uri"/>.
        /// </summary>
        /// <typeparam name="T">The resource entity type.</typeparam>
        /// <param name="uri">The URI.</param>
        /// <returns>The ACME response.</returns>
        public async Task<AcmeRespone<T>> Get<T>(Uri uri)
        {
            var resp = await http.GetAsync(uri);
            var result = await ReadResponse<T>(resp);
            return result;
        }

        /// <summary>
        /// Performs HTTP POST to <paramref name="uri"/>.
        /// </summary>
        /// <typeparam name="T">The resource entity type.</typeparam>
        /// <param name="uri">The URI.</param>
        /// <param name="entity">The entity.</param>
        /// <param name="keyPair">The signing key pair.</param>
        /// <returns>The ACME response.</returns>
        public async Task<AcmeRespone<T>> Post<T>(Uri uri, T entity, IAccountKey keyPair)
            where T : EntityBase
        {
            await FetchDirectory(false);

            var content = await GenerateRequestContent(entity, keyPair);
            var resp = await http.PostAsync(uri, content);
            var result = await ReadResponse<T>(resp, entity.Resource);
            return result;
        }

        /// <summary>
        /// Encodes the specified entity for ACME requests.
        /// </summary>
        /// <param name="entity">The entity.</param>
        /// <param name="keyPair">The key pair.</param>
        /// <param name="nonce">The nonce.</param>
        /// <returns>The encoded JSON.</returns>
        private static object Encode(EntityBase entity, IAccountKey keyPair, string nonce)
        {
            var jsonSettings = JsonUtil.CreateSettings();
            var unprotectedHeader = new
            {
                alg = keyPair.Algorithm.ToJwsAlgorithm(),
                jwk = keyPair.Jwk
            };

            var protectedHeader = new
            {
                nonce = nonce
            };

            var entityJson = JsonConvert.SerializeObject(entity, Formatting.None, jsonSettings);
            var protectedHeaderJson = JsonConvert.SerializeObject(protectedHeader, Formatting.None, jsonSettings);

            var payloadEncoded = JwsConvert.ToBase64String(Encoding.UTF8.GetBytes(entityJson));
            var protectedHeaderEncoded = JwsConvert.ToBase64String(Encoding.UTF8.GetBytes(protectedHeaderJson));

            var signature = $"{protectedHeaderEncoded}.{payloadEncoded}";
            var signatureBytes = Encoding.ASCII.GetBytes(signature);
            var signedSignatureBytes = keyPair.SignData(signatureBytes);
            var signedSignatureEncoded = JwsConvert.ToBase64String(signedSignatureBytes);

            var body = new
            {
                header = unprotectedHeader,
                @protected = protectedHeaderEncoded,
                payload = payloadEncoded,
                signature = signedSignatureEncoded
            };

            return body;
        }

        private async Task FetchDirectory(bool force)
        {
            if (this.directory == null || force)
            {
                var uri = serverUri;
                var resp = await this.Get<Resource.Directory>(uri);
                this.directory = resp.Data;
            }
        }

        private async ValueTask<string> GetNonce()
        {
            var nonce = Interlocked.Exchange(ref nextNonce, null);
            while (nonce == null)
            {
                // TODO: fetch from new-nonce resource
                await FetchDirectory(true);
                nonce = Interlocked.Exchange(ref nextNonce, null);
            }

            return nonce;
        }

        private async ValueTask<StringContent> GenerateRequestContent(EntityBase entity, IAccountKey keyPair)
        {
            var nonce = await this.GetNonce();
            var body = Encode(entity, keyPair, nonce);
            var bodyJson = JsonConvert.SerializeObject(body, Formatting.None, jsonSettings);

            return new StringContent(bodyJson, Encoding.ASCII, MimeJson);
        }

        private async Task<AcmeRespone<T>> ReadResponse<T>(HttpResponseMessage response, string resourceType = null)
        {
            var data = new AcmeRespone<T>();
            if (IsJsonMedia(response.Content.Headers.ContentType.MediaType))
            {
                var json = await response.Content.ReadAsStringAsync();
                data.Json = json;
                if (response.IsSuccessStatusCode)
                {
                    data.Data = JsonConvert.DeserializeObject<T>(json, jsonSettings);
                    var entity = data.Data as EntityBase;
                    if (resourceType != null && entity != null && string.IsNullOrWhiteSpace(entity.Resource))
                    {
                        entity.Resource = resourceType;
                    }
                }
                else
                {
                    data.Error = JsonConvert.DeserializeObject<AcmeError>(json, jsonSettings);
                }
            }
            else if (response.Content.Headers.ContentLength > 0)
            {
                data.Raw = await response.Content.ReadAsByteArrayAsync();
            }

            ParseHeaders(data, response);
            this.nextNonce = data.ReplayNonce;
            return data;
        }

        private static void ParseHeaders<T>(AcmeRespone<T> data, HttpResponseMessage response)
        {
            data.Location = response.Headers.Location;

            if (response.Headers.Contains("Replay-Nonce"))
            {
                data.ReplayNonce = response.Headers.GetValues("Replay-Nonce").Single();
            }

            // TODO: Support Retry-After header

            if (response.Headers.Contains("Link"))
            {

                data.Links = response.Headers.GetValues("Link")?
                    .Select(h =>
                    {
                        var segments = h.Split(';');
                        var url = segments[0].Substring(1, segments[0].Length - 2);
                        var rel = segments.Skip(1)
                            .Select(s => s.Trim())
                            .Where(s => s.StartsWith("rel=", StringComparison.OrdinalIgnoreCase))
                            .Select(r =>
                            {
                                var relType = r.Split('=')[1];
                                return relType.Substring(1, relType.Length - 2);
                            })
                            .First();

                        return new RelLink
                        {
                            Rel = rel,
                            Uri = new Uri(url)
                        };
                    })
                    .ToArray();
            }

            data.ContentType = response.Content.Headers.ContentType.MediaType;
        }

        private static bool IsJsonMedia(string mediaType)
        {
            if (mediaType != null && mediaType.StartsWith("application/"))
            {
                return mediaType
                    .Substring("application/".Length)
                    .Split('+')
                    .Any(t => t == "json");
            }

            return false;
        }

        #region IDisposable Support
        private bool disposedValue = false;

        /// <summary>
        /// Releases unmanaged and - optionally - managed resources.
        /// </summary>
        /// <param name="disposing"><c>true</c> to release both managed and unmanaged resources; <c>false</c> to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (this.shouldDisposeHander)
                    {
                        http?.Dispose();
                    }
                }
                
                disposedValue = true;
            }
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
