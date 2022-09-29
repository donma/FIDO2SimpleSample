


string ServerDomain = "localhost";
var serverName = "DFIDO2-TEST";
var origin = "https://localhost:7091";


var builder = WebApplication.CreateBuilder(args);


//Ref ro services
var services = builder.Services;



// Use the in-memory implementation of IDistributedCache.
services.AddMemoryCache();
services.AddDistributedMemoryCache();
//for not check required
services.AddControllers(options => options.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes = true)
//for json response result.
.AddJsonOptions(opts => opts.JsonSerializerOptions.PropertyNamingPolicy = null);



//Add Session
builder.Services.AddSession(options =>
{
    // Set a short timeout for easy testing.
    options.IdleTimeout = TimeSpan.FromMinutes(2);
    options.Cookie.HttpOnly = true;
    // Strict SameSite mode is required because the default mode used
    // by ASP.NET Core 3 isn't understood by the Conformance Tool
    // and breaks conformance testing
    options.Cookie.SameSite = SameSiteMode.Unspecified;
});


//add FIDO2
builder.Services.AddFido2(options =>
{
    options.ServerDomain = ServerDomain;
    options.ServerName = serverName;
    options.Origins = new HashSet<string> { origin };
    options.TimestampDriftTolerance = 300_000;
    // options.MDSCacheDirPath = Configuration["fido2:MDSCacheDirPath"];
})
.AddCachedMetadataService(config =>
{
  config.AddFidoMetadataRepository(httpClientBuilder =>
  {
      //TODO: any specific config you want for accessing the MDS
  });
});



// Add services to the container.
builder.Services.AddRazorPages();



var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}



app.UseSession();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

//use Web API
app.MapControllers();

app.Run();
