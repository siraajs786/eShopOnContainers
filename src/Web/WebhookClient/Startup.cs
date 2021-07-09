using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenTelemetry.Exporter;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using System;
using System.Linq;
using System.Net;
using System.Threading;
using WebhookClient.Services;

namespace WebhookClient
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSession(opt =>
                {
                    opt.Cookie.Name = ".eShopWebhooks.Session";
                })
                .AddConfiguration(Configuration)
                .AddHttpClientServices(Configuration)
                .AddCustomAuthentication(Configuration)
                .AddTransient<IWebhooksClient, WebhooksClient>()
                .AddSingleton<IHooksRepository, InMemoryHooksRepository>()
                .AddMvc()
                .SetCompatibilityVersion(CompatibilityVersion.Version_3_0);

            services.AddControllers();

            // if USE_EXPORTER value is  'otlp' code will configure Otlp collector with zipkin receiver
            // or only 'zipkin' then zipkin exporter is configured or 'jaeger' only jaeger exporter is configured as per appsettings.json or .env file.
            var exporter = Environment.GetEnvironmentVariable("USE_EXPORTER");
            if (exporter == null && this.Configuration.GetValue<string>("USE_EXPORTER").ToLowerInvariant() != "")
            {
                exporter = this.Configuration.GetValue<string>("USE_EXPORTER").ToLowerInvariant();
            }
            switch (exporter)
            {
                case "jaeger":
                    services.AddOpenTelemetryTracing((builder) => builder
                        .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(System.Reflection.Assembly.GetExecutingAssembly().ToString().Split(",")[0]))
                        .AddAspNetCoreInstrumentation()
                        .AddGrpcClientInstrumentation()
                        .AddHttpClientInstrumentation()
                        .AddJaegerExporter());
                    services.Configure<JaegerExporterOptions>(this.Configuration.GetSection("Jaeger"));
                    break;
                case "zipkin":
                    services.AddOpenTelemetryTracing((builder) => builder
                        .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(System.Reflection.Assembly.GetExecutingAssembly().ToString().Split(",")[0]))
                        .AddAspNetCoreInstrumentation()
                        .AddGrpcClientInstrumentation()
                        .AddHttpClientInstrumentation()
                        .AddZipkinExporter());

                    services.Configure<ZipkinExporterOptions>(this.Configuration.GetSection("Zipkin"));
                    break;
                case "otlp":
                    // Adding the OtlpExporter creates a GrpcChannel.
                    // This switch must be set before creating a GrpcChannel/HttpClient when calling an insecure gRPC service.
                    // See: https://docs.microsoft.com/aspnet/core/grpc/troubleshoot#call-insecure-grpc-services-with-net-core-client
                    AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

                    services.AddOpenTelemetryTracing((builder) => builder
                        .SetResourceBuilder(ResourceBuilder.CreateDefault().AddService(System.Reflection.Assembly.GetExecutingAssembly().ToString().Split(",")[0]))
                        .AddAspNetCoreInstrumentation()
                        .AddHttpClientInstrumentation()
                        .AddOtlpExporter(otlpOptions =>
                        {
                            otlpOptions.Endpoint = new Uri(this.Configuration.GetValue<string>("Otlp:Endpoint"));
                        }));
                    break;
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {

            var pathBase = Configuration["PATH_BASE"];
            if (!string.IsNullOrEmpty(pathBase))
            {
                app.UsePathBase(pathBase);
            }

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
            }
            app.UseAuthentication();
            app.Map("/check", capp =>
            {
                capp.Run(async (context) =>
                {
                    if ("OPTIONS".Equals(context.Request.Method, StringComparison.InvariantCultureIgnoreCase))
                    {
                        var validateToken = bool.TrueString.Equals(Configuration["ValidateToken"], StringComparison.InvariantCultureIgnoreCase);
                        var header = context.Request.Headers[HeaderNames.WebHookCheckHeader];
                        var value = header.FirstOrDefault();
                        var tokenToValidate = Configuration["Token"];
                        if (!validateToken || value == tokenToValidate)
                        {
                            if (!string.IsNullOrWhiteSpace(tokenToValidate))
                            {
                                context.Response.Headers.Add(HeaderNames.WebHookCheckHeader, tokenToValidate);
                            }
                            context.Response.StatusCode = (int)HttpStatusCode.OK;
                        }
                        else
                        {
                            await context.Response.WriteAsync("Invalid token");
                            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                        }
                    }
                    else
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    }
                });
            });
            app.UseStaticFiles();
            app.UseSession();
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }

    static class ServiceExtensions
    {
        public static IServiceCollection AddConfiguration(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddOptions();
            services.Configure<Settings>(configuration);
            return services;
        }
        public static IServiceCollection AddCustomAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            var identityUrl = configuration.GetValue<string>("IdentityUrl");
            var callBackUrl = configuration.GetValue<string>("CallBackUrl");

            // Add Authentication services          

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(setup => setup.ExpireTimeSpan = TimeSpan.FromHours(2))
            .AddOpenIdConnect(options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.Authority = identityUrl.ToString();
                options.SignedOutRedirectUri = callBackUrl.ToString();
                options.ClientId = "webhooksclient";
                options.ClientSecret = "secret";
                options.ResponseType = "code id_token";
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.RequireHttpsMetadata = false;
                options.Scope.Add("openid");
                options.Scope.Add("webhooks");
            });

            return services;
        }

        public static IServiceCollection AddHttpClientServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddTransient<HttpClientAuthorizationDelegatingHandler>();
            services.AddHttpClient("extendedhandlerlifetime").SetHandlerLifetime(Timeout.InfiniteTimeSpan);

            //add http client services
            services.AddHttpClient("GrantClient")
                   .SetHandlerLifetime(TimeSpan.FromMinutes(5))
                   .AddHttpMessageHandler<HttpClientAuthorizationDelegatingHandler>();

            return services;
        }
    }
}
