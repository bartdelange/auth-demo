using Api.config;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.ConfigureAuthorization();
builder.ConfigureSwagger();

var app = builder.Build();
app.MapControllers();
app.ConfigureAuthorization();
app.ConfigureSwagger();


app.Run("https://localhost:3000");
