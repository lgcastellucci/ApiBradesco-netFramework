using System;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using static BoletoHibridoBradesco.Security.Signer;
using BoletoHibridoBradesco.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using BoletoHibridoBradesco.Loaders;

namespace BoletoHibridoBradesco
{
    internal class Program
    {
        #region Private Fields

        private static HttpClient client;

        #endregion Private Fields

        #region Private Methods

        /// <summary>
        /// Consulta debitos Veiculares
        /// </summary>
        /// <param name="token">Token de acesso</param>
        /// <param name="assertion">"assertion" criada anteriormente</param>
        /// <param name="certificate">Certificado</param>
        /// <returns></returns>
        /// <exception cref="Exception">Exceções gerais</exception>
        private static async Task CheckDebitAsync(string token, string clientDocument, SignedAssertion assertion, X509Certificate2 certificate)
        {
            string uri = "/v1/arcd/debito-veiculo/ba/lista-debitos/listaDebitos/renavan";
            string url = "https://proxy.api.prebanco.com.br/v1/arcd/debito-veiculo/ba/lista-debitos/listaDebitos/renavan";

            //Este json é/foi fornecido pelo suporte Bradesco.
            var json = "";
            json += "{";
            json += "\"codigoBanco\": \"237\",";
            json += "\"codigoAgencia\": \"145\",";
            json += "\"codigoConta\": \"999\",";
            json += "\"codigoRenavam\": \"1125879278\",";
            json += "\"anoExercicio\": \"2024\",";
            json += "\"codigoPagamento\": \"409\",";
            json += "\"validacaoListaPositiva\": \"N\",";
            json += "\"codigoCanal\": \"66\"";
            json += "}";

            //nonce, lembra da criação do "assertion"?
            var nonce = assertion.Jti;

            //O cabeçalho X-Brad-Signature precisa do json do boleto
            var xBrad = Signer.CreateXBradSignature(token, assertion.Timestamp, uri, "", json, nonce, certificate);

            //prepara os headers
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("X-Brad-Signature", xBrad);//criada e assinada anteriormente
            client.DefaultRequestHeaders.Add("X-Brad-Nonce", nonce.ToString()); //jti criado no momento do "assertion"
            client.DefaultRequestHeaders.Add("X-Brad-Timestamp", assertion.Timestamp); // timestamp criado no momento do "assertion"
            client.DefaultRequestHeaders.Add("X-Brad-Algorithm", "SHA256");
            client.DefaultRequestHeaders.Add("Authorization", token); // token solicitado no serviço de autenticação do Bradesco

            //conteúdo
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            //Registrar o boleto
            var response = await client.PostAsync(url, content);
            json = await response.Content.ReadAsStringAsync();

            //Se tudo correu bem, é um sucesso e o boleto foi registrado
            if (!response.IsSuccessStatusCode)
            {
                //Xii! Deu erro
                throw new Exception(json);
            }
            Console.WriteLine(json);
            Console.WriteLine("Consulta realizada com sucesso.");
        }


        /// <summary>
        /// Cria um boleto
        /// </summary>
        /// <param name="token">Token de acesso</param>
        /// <param name="assertion">"assertion" criada anteriormente</param>
        /// <param name="certificate">Certificado</param>
        /// <returns></returns>
        /// <exception cref="Exception">Exceções gerais</exception>
        private static async Task CreateBilletAsync(string token, string clientDocument, SignedAssertion assertion, X509Certificate2 certificate)
        {
            string uri = "/v1/boleto-hibrido/registrar-boleto";
            string url = "https://proxy.api.prebanco.com.br/v1/boleto-hibrido/registrar-boleto";

            //Este json é/foi fornecido pelo suporte Bradesco.
            var json = "";
            json += "{";
            json += "\"ctitloCobrCdent\": \"" + clientDocument.Substring(0, 8) + "025" + "\","; // "UTILIZAR A RAIZ DO CNPJ DA EMPRESA + NÚMEROS SEQUENCIAIS - EX: 01234567001"
            json += "\"registrarTitulo\": \"1\",";
            json += "\"codUsuario\": \"APISERVIC\",";
            json += "\"nroCpfCnpjBenef\": \"68542653\",";
            json += "\"filCpfCnpjBenef\": \"1018\",";
            json += "\"digCpfCnpjBenef\": \"38\",";
            json += "\"tipoAcesso\": \"2\",";
            json += "\"cpssoaJuridContr\": \"2269651\",";
            json += "\"ctpoContrNegoc\": \"48\",";
            json += "\"nseqContrNegoc\": \"2170272\",";
            json += "\"cidtfdProdCobr\": \"09\",";
            json += "\"cnegocCobr\": \"386100000000041000\",";
            json += "\"filler\": \"\",";
            json += "\"codigoBanco\": \"237\",";
            json += "\"eNseqContrNegoc\": \"2170272\",";
            json += "\"tipoRegistro\": \"001\",";
            json += "\"cprodtServcOper\": \"00000000\",";
            json += "\"ctitloCliCdent\": \"CTITLO-CLI-CDENT\",";
            json += "\"demisTitloCobr\": \"08.07.2024\",";
            json += "\"dvctoTitloCobr\": \"10.07.2024\",";
            json += "\"cidtfdTpoVcto\": \"0\",";
            json += "\"cindcdEconmMoeda\": \"00006\",";
            json += "\"vnmnalTitloCobr\": \"00000000000100000\",";
            json += "\"qmoedaNegocTitlo\": \"00000000000100000\",";
            json += "\"cespceTitloCobr\": \"10\",";
            json += "\"cindcdAceitSacdo\": \"N\",";
            json += "\"ctpoProteTitlo\": \"00\",";
            json += "\"ctpoPrzProte\": \"07\",";
            json += "\"ctpoProteDecurs\": \"00\",";
            json += "\"ctpoPrzDecurs\": \"07\",";
            json += "\"cctrlPartcTitlo\": \"CCTRL-PARTC-TITLO\",";
            json += "\"cformaEmisPplta\": \"01\",";
            json += "\"cindcdPgtoParcial\": \"N\",";
            json += "\"qtdePgtoParcial\": \"000\",";
            json += "\"filler1\": \"\",";
            json += "\"ptxJuroVcto\": \"0\",";
            json += "\"vdiaJuroMora\": \"\",";
            json += "\"qdiaInicJuro\": \"0\",";
            json += "\"pmultaAplicVcto\": \"0\",";
            json += "\"vmultaAtrsoPgto\": \"0\",";
            json += "\"qdiaInicMulta\": \"0\",";
            json += "\"pdescBonifPgto01\": \"0\",";
            json += "\"vdescBonifPgto01\": \"0\",";
            json += "\"dlimDescBonif1\": \"\",";
            json += "\"pdescBonifPgto02\": \"0\",";
            json += "\"vdescBonifPgto02\": \"0\",";
            json += "\"dlimDescBonif2\": \"\",";
            json += "\"pdescBonifPgto03\": \"0\",";
            json += "\"vdescBonifPgto03\": \"0\",";
            json += "\"dlimDescBonif3\": \"\",";
            json += "\"ctpoPrzCobr\": \"0\",";
            json += "\"pdescBonifPgto\": \"0\",";
            json += "\"vdescBonifPgto\": \"0\",";
            json += "\"dlimBonifPgto\": \"\",";
            json += "\"vabtmtTitloCobr\": \"0\",";
            json += "\"viofPgtoTitlo\": \"0\",";
            json += "\"filler2\": \"\",";
            json += "\"isacdoTitloCobr\": \"SACADOTESTE\",";
            json += "\"elogdrSacdoTitlo\": \"LOGRADOUROSACADOTESTE\",";
            json += "\"enroLogdrSacdo\": \"LOGRADOURO\",";
            json += "\"ecomplLogdrSacdo\": \"LOGRADOUROSACA\",";
            json += "\"ccepSacdoTitlo\": \"06401\",";
            json += "\"ccomplCepSacdo\": \"160\",";
            json += "\"ebairoLogdrSacdo\": \"BAIRROSACADO\",";
            json += "\"imunSacdoTitlo\": \"MUNICIPIOSACADO\",";
            json += "\"csglUfSacdo\": \"SP\",";
            json += "\"indCpfCnpjSacdo\": \"1\",";
            json += "\"nroCpfCnpjSacdo\": \"00045886591893\",";
            json += "\"renderEletrSacdo\": \"ENDERECOSACADO\",";
            json += "\"cdddFoneSacdo\": \"011\",";
            json += "\"cfoneSacdoTitlo\": \"00989414444\",";
            json += "\"bancoDeb\": \"000\",";
            json += "\"agenciaDeb\": \"00000\",";
            json += "\"agenciaDebDv\": \"0\",";
            json += "\"contaDeb\": \"0000000000000\",";
            json += "\"bancoCentProt\": \"237\",";
            json += "\"agenciaDvCentPr\": \"4152\",";
            json += "\"isacdrAvalsTitlo\": \"\",";
            json += "\"elogdrSacdrAvals\": \"\",";
            json += "\"enroLogdrSacdr\": \"\",";
            json += "\"ecomplLogdrSacdr\": \"\",";
            json += "\"ccepSacdrTitlo\": \"0\",";
            json += "\"ccomplCepSacdr\": \"0\",";
            json += "\"ebairoLogdrSacdr\": \"\",";
            json += "\"imunSacdrAvals\": \"\",";
            json += "\"csglUfSacdr\": \"\",";
            json += "\"indCpfCnpjSacdr\": \"0\",";
            json += "\"nroCpfCnpjSacdr\": \"0\",";
            json += "\"renderEletrSacdr\": \"\",";
            json += "\"cdddFoneSacdr\": \"0\",";
            json += "\"cfoneSacdrTitlo\": \"0\",";
            json += "\"filler3\": \"\",";
            json += "\"fase\": \"1\",";
            json += "\"cindcdCobrMisto\": \"S\",";
            json += "\"ialiasAdsaoCta\": \"\",";
            json += "\"iconcPgtoSpi\": \"\",";
            json += "\"caliasAdsaoCta\": \"\",";
            json += "\"ilinkGeracQrcd\": \"\",";
            json += "\"wqrcdPdraoMercd\": \"\",";
            json += "\"validadeAposVencimento\": \"0\",";
            json += "\"filler4\": \"\"";
            json += "}";

            //nonce, lembra da criação do "assertion"?
            var nonce = assertion.Jti;

            //O cabeçalho X-Brad-Signature precisa do json do boleto
            var xBrad = Signer.CreateXBradSignature(token, assertion.Timestamp, uri, "", json, nonce, certificate);

            //prepara os headers
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("X-Brad-Signature", xBrad);//criada e assinada anteriormente
            client.DefaultRequestHeaders.Add("X-Brad-Nonce", nonce.ToString()); //jti criado no momento do "assertion"
            client.DefaultRequestHeaders.Add("X-Brad-Timestamp", assertion.Timestamp); // timestamp criado no momento do "assertion"
            client.DefaultRequestHeaders.Add("X-Brad-Algorithm", "SHA256");
            client.DefaultRequestHeaders.Add("Authorization", token); // token solicitado no serviço de autenticação do Bradesco

            //Em produçao precisa do cnpj
            //client.DefaultRequestHeaders

            //conteúdo
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            //Registrar o boleto
            var response = await client.PostAsync(url, content);
            json = await response.Content.ReadAsStringAsync();

            //Se tudo correu bem, é um sucesso e o boleto foi registrado
            if (!response.IsSuccessStatusCode)
            {
                //Xii! Deu erro
                throw new Exception(json);
            }
            Console.WriteLine(json);
            Console.WriteLine("O boleto foi gerado com sucesso.");
        }

        /// <summary>
        /// Valida acesso a API do Bradesco
        /// </summary>
        /// <param name="token">Token de acesso</param>
        /// <param name="assertion">"assertion" criada anteriormente</param>
        /// <param name="certificate">Certificado</param>
        /// <returns></returns>
        /// <exception cref="Exception">Exceções gerais</exception>
        private static async Task ValidateAccessAccount(string token, string agency, string account, SignedAssertion assertion, X509Certificate2 certificate)
        {
            var url = "https://proxy.api.prebanco.com.br/v1.1/jwt-service?agencia=" + agency + "&conta=" + account;
            var uri = "/v1.1/jwt-service";

            var parameters = "agencia=" + agency + "&conta=" + account;

            //Este json é em branco pois nenhum dado é enviado, apesar de ser POST
            var json = "";

            //nonce, lembra da criação do "assertion"?
            var nonce = assertion.Jti;

            //O cabeçalho X-Brad-Signature precisa do json do boleto
            var xBrad = Signer.CreateXBradSignature(token, assertion.Timestamp, uri, parameters, json, nonce, certificate);

            //prepara os headers
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add("X-Brad-Signature", xBrad);//criada e assinada anteriormente
            client.DefaultRequestHeaders.Add("X-Brad-Nonce", nonce.ToString()); //jti criado no momento do "assertion"
            client.DefaultRequestHeaders.Add("X-Brad-Timestamp", assertion.Timestamp); // timestamp criado no momento do "assertion"
            client.DefaultRequestHeaders.Add("X-Brad-Algorithm", "SHA256");
            client.DefaultRequestHeaders.Add("Authorization", token); // token solicitado no serviço de autenticação do Bradesco

            //conteúdo
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            //Registrar o boleto
            var response = await client.PostAsync(url, content);
            json = await response.Content.ReadAsStringAsync();

            //Se tudo correu bem, é um sucesso e o boleto foi registrado
            if (!response.IsSuccessStatusCode)
            {
                //Xii! Deu erro
                throw new Exception(json);
            }

            Console.WriteLine("Acesso feito com sucesso.");
        }

        /// <summary>
        /// Gera um token e retorna
        /// </summary>
        /// <param name="clientId">Client_Id obtido junto ao banco Bradesco</param>
        /// <param name="certificate">Certificado enviado ao Bradesco para obtenção do Client_Id</param>
        /// <returns></returns>
        /// <exception cref="Exception">Exceção genérica</exception>
        private static async Task<(SignedAssertion Assertion, string Token)> GetTokenAsync(string clientId, X509Certificate2 certificate)
        {
            // Assinar e criar o Assertion, necessário para a solicitação do token do Bradesco
            var assertion = Signer.CreateAssertion(clientId, certificate);

            //Criar o http client para a requisição do token
            var client = new HttpClient();

            //prepara os headers
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Connection.Add("keep-alive");
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

            //conteúdo
            List<KeyValuePair<string, string>> keyValues = new List<KeyValuePair<string, string>>();
            keyValues.Add(new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"));
            keyValues.Add(new KeyValuePair<string, string>("assertion", assertion.Assertion));
            string stringContent = new FormUrlEncodedContent(keyValues).ReadAsStringAsync().Result;
            var content = new StringContent(stringContent, Encoding.UTF8, "application/x-www-form-urlencoded");

            //Buscar o token
            var url = "https://proxy.api.prebanco.com.br/auth/server/v1.2/token";

            //zignet
            if (clientId == "123")
                url = "https://proxy.api.prebanco.com.br/auth/server/v1.1/token";

            var response = await client.PostAsync(url, content);
            var json = await response.Content.ReadAsStringAsync();

            //Se tudo correu bem, é um sucesso e o token foi gerado
            if (response.IsSuccessStatusCode)
            {
                var token = JsonConvert.DeserializeObject<JToken>(json)["access_token"].ToString();
                return (assertion, token);
            }

            //Xii! Deu erro
            throw new Exception(json);
        }

        private static void Main(string[] args)
        {
            /*
            ///Recebido do Bradesco para homologação na via pfx
            var clientId = "12345678-1234-1234-1234-6f1826dbbd43";
            var clientDocument = "12345678901234";

            var agency = "1111";
            var account = "22222";

            //Certificado enviado para o Bradesco para a criação do Client Id
            var certificate = new X509Certificate2(@"C:\certificado.pfx", "123456");
            */


            // Dados da via pen
            var clientId = "12345678-1234-1234-1234-6f1826dbbd43";
            var clientDocument = "12345678901234";

            var agency = "1111";
            var account = "22222";
            var certificate = CertificatePEM.LoadCertificateFromPem(@"C:\public.pem", @"C:\private.pem");
 


            Console.Title = "Boleto Hibrido Bradesco";
            Console.WriteLine("Olá, vamos emitir um boleto com QR Code!");
            MainAsync(clientId, clientDocument, agency, account, certificate).Wait();
            Console.ReadKey();
        }

        private static async Task MainAsync(string clientId, string clientDocument, string agency, string account, X509Certificate2 certificate)
        {
            var token = (Assertion: default(SignedAssertion), Token: string.Empty);
            try
            {
                Console.WriteLine("Requisitando token.");

                //Aqui, vamos buscar o token
                token = await GetTokenAsync(clientId, certificate);

                Console.WriteLine("Token retornado com sucesso!");
                Console.WriteLine(token.Token);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro");
                Console.WriteLine(ex.Message);
            }

            if (string.IsNullOrEmpty(token.Token))
                return;

            try
            {
                if (clientId != "da64cb8d-763f-4a45-9305-3301a1ad208f")
                {
                    Console.WriteLine("Validando o acesso.");

                    //De posse do token, iremos validar o acesso a conta
                    await ValidateAccessAccount(token.Token, agency, account, token.Assertion, certificate);

                    Console.WriteLine("Acesso validado.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro");
                Console.WriteLine(ex.Message);
            }

            try
            {
                if (clientId != "da64cb8d-763f-4a45-9305-3301a1ad208f")
                {
                    Console.WriteLine("Criar Boleto.");

                    //De posse do token, iremos criar o boleto.
                    await CreateBilletAsync(token.Token, clientDocument, token.Assertion, certificate);

                    Console.WriteLine("Criar Boleto com sucesso.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro");
                Console.WriteLine(ex.Message);
            }

            try
            {
                if (clientId == "da64cb8d-763f-4a45-9305-3301a1ad208f")
                {
                    Console.WriteLine("Consultar Debitos.");

                    //De posse do token, iremos criar o boleto.
                    await CheckDebitAsync(token.Token, clientDocument, token.Assertion, certificate);

                    Console.WriteLine("Consultar Debitos com sucesso.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Erro");
                Console.WriteLine(ex.Message);
            }
        }

        #endregion Private Methods
    }
}
