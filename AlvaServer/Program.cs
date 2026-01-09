using AlvaServer.Services;
using AlvaServer.Models;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

// 1. Setup Builder
var builder = WebApplication.CreateBuilder(args);

// 2. Register Services
builder.Services.AddSingleton<UserStore>();
builder.Services.AddSingleton<MessageStore>();
AuthUtils.RegisterJwtServices(builder); // Setup Auth

var app = builder.Build();

// 3. Activate Security
app.UseAuthentication();
app.UseAuthorization();

// =====================
// API ENDPOINTS
// =====================

// POST /register
app.MapPost("/register", (UserStore userStore, [FromBody] UserDto req) =>
{
    if (userStore.UserExists(req.Username))
        return Results.Conflict("Username taken");

    var (hash, salt) = AuthUtils.HashPassword(req.Password, req.Username);
    
    var newUser = new User 
    { 
        Username = req.Username, 
        PasswordHash = hash, 
        Salt = salt,
        // FIX: Actually save the key from the request!
        PublicKeyXml = req.PublicKeyXml 
    };
    
    userStore.AddUser(newUser);
    return Results.Ok("User created");
});

// POST /login
app.MapPost("/login", (UserStore userStore, [FromBody] UserDto req) =>
{
    var user = userStore.GetUser(req.Username);
    if (user == null) 
        return Results.Unauthorized();

    if (!AuthUtils.VerifyPassword(req.Password, req.Username, user.PasswordHash, user.Salt))
        return Results.Unauthorized();

    var token = AuthUtils.GenerateJwt(user.Username);
    return Results.Ok(new { Token = token });
});

// POST /send
app.MapPost("/send", (MessageStore msgStore, ClaimsPrincipal user, [FromBody] SendMessageRequest req) =>
{
    var sender = user.Identity?.Name;
    if (string.IsNullOrEmpty(sender)) return Results.Unauthorized();

    msgStore.SaveMessage(sender, req.Recipient, req.EncryptedContent);
    return Results.Ok("Message stored");
}).RequireAuthorization();

// GET /inbox
// This creates a URL like: http://localhost:5000/key/bob
app.MapGet("/key/{username}", (UserStore userStore, string username) =>
{
    // 1. Look up "bob" in the database
    var user = userStore.GetUser(username);
    
    // 2. If Bob doesn't exist, say "Not Found" (404)
    if (user == null) return Results.NotFound();
    
    // 3. If Bob is found, return ONLY his Public Key.
    // We do NOT return his PasswordHash or Salt! Only the public stuff.
    return Results.Ok(new { Key = user.PublicKeyXml });
});

app.Run();

// ==================================================
// IMPORTANT: THESE MUST BE AT THE BOTTOM OF THE FILE
// ==================================================
record UserDto(string Username, string Password, string PublicKeyXml); // Added PublicKeyXml
// Update the /register endpoint to save req.PublicKeyXml
record SendMessageRequest(string Recipient, byte[] EncryptedContent);