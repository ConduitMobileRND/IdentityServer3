/*
 * Copyright 2014 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Configuration;
using Microsoft.Owin;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Twitter;
using Owin;
using Thinktecture.IdentityManager.Configuration;
using Thinktecture.IdentityServer.Core.Configuration;
using Thinktecture.IdentityServer.Core.Logging;
using Thinktecture.IdentityServer.Host;
using Thinktecture.IdentityServer.Host.Config;
using Thinktecture.IdentityServer.Host.IdMgr;

[assembly: OwinStartup("Como", typeof(Startup))]

namespace Thinktecture.IdentityServer.Host
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            LogProvider.SetCurrentLogProvider(new DiagnosticsTraceLogProvider());

            // uncomment to enable HSTS headers for the host
            // see: https://developer.mozilla.org/en-US/docs/Web/Security/HTTP_strict_transport_security
            //app.UseHsts();

            app.Map("/admin", adminApp =>
            {
                var factory = new IdentityManagerServiceFactory();
                factory.ConfigureSimpleIdentityManagerService("AspId");

                adminApp.UseIdentityManager(new IdentityManagerOptions()
                {
                    Factory = factory
                });
            });


            app.Map("/core", coreApp =>
                {
                    //In order to run server under hard coded collection of
                    //iusers use following configuration: var factory =
                    //InMemoryFactory.Create(
                    //    users:   Users.Get(),
                    //    clients: Clients.Get(),
                    //    scopes:  Scopes.Get());

                    var idSvrFactory = Factory.Configure();
                    idSvrFactory.ConfigureUserService("AspId");



                    var idsrvOptions = new IdentityServerOptions
                    {
                        Factory = idSvrFactory,
                        SigningCertificate = Cert.Load(),

                        CorsPolicy = CorsPolicy.AllowAll,

                        AuthenticationOptions = new AuthenticationOptions
                        {
                            IdentityProviders = ConfigureIdentityProviders,
                            EnableSignOutPrompt = false,
                            //operating cookies here
                        },

                        LoggingOptions = new LoggingOptions
                        {
                            //EnableHttpLogging = true, 
                            //EnableWebApiDiagnostics = true,
                            //IncludeSensitiveDataInLogs = true
                        },

                        EventsOptions = new EventsOptions
                        {
                            RaiseFailureEvents = true,
                            RaiseInformationEvents = true,
                            RaiseSuccessEvents = true,
                            RaiseErrorEvents = true
                        },
                        
                        
                    };

                    coreApp.UseIdentityServer(idsrvOptions);
                });
        }

        public static void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
            var google = new GoogleOAuth2AuthenticationOptions
            {
                AuthenticationType = "Google",
                Caption = "Google",
                SignInAsAuthenticationType = signInAsType,

                ClientId = ConfigurationManager.AppSettings["googleclientid"],
                ClientSecret = ConfigurationManager.AppSettings["googleclientsecret"]
            };
            app.UseGoogleAuthentication(google);

            var fb = new FacebookAuthenticationOptions
            {
                AuthenticationType = "Facebook",
                Caption = "Facebook",
                SignInAsAuthenticationType = signInAsType,

                AppId = ConfigurationManager.AppSettings["facebookappid"],
                AppSecret = ConfigurationManager.AppSettings["facebookappsecret"]
            };
            app.UseFacebookAuthentication(fb);

            var twitter = new TwitterAuthenticationOptions
            {
                AuthenticationType = "Twitter",
                Caption = "Twitter",
                SignInAsAuthenticationType = signInAsType,
                
                ConsumerKey = "N8r8w7PIepwtZZwtH066kMlmq",
                ConsumerSecret = "df15L2x6kNI50E4PYcHS0ImBQlcGIt6huET8gQN41VFpUCwNjM"
            };
            app.UseTwitterAuthentication(twitter);
        }
    }
}