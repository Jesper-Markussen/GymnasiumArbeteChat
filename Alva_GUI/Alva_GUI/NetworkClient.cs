using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace Alva_V1;

public class NetworkClient
{
    private readonly HttpClient _http;
    private string _authToken = "";

    public NetworkClient(string serverUrl = "http://localhost:5000")
    {
        _http = new HttpClient { BaseAddress = new Uri(serverUrl) };
    }

    // 1. Register a new user
    public async Task<bool> RegisterAsync(string username, string password, string publicKeyXml)
    {
        var response = await _http.PostAsJsonAsync("/register", new
        {
            Username = username,
            Password = password,
            PublicKeyXml = publicKeyXml
        });
        return response.IsSuccessStatusCode;
    }

    // 2. Login (Get the "Badge")
    public async Task<bool> LoginAsync(string username, string password)
    {
        var response = await _http.PostAsJsonAsync("/login", new { Username = username, Password = password });

        if (!response.IsSuccessStatusCode) return false;

        var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
        if (result is not null)
        {
            _authToken = result.Token;
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _authToken);
            return true;
        }
        return false;
    }

    // 3. Get someone's Public Key (The "Phonebook" lookup)
    public async Task<string?> GetPublicKeyAsync(string username)
    {
        try
        {
            var response = await _http.GetFromJsonAsync<PublicKeyResponse>($"/key/{username}");
            return response?.Key;
        }
        catch
        {
            return null; // User not found
        }
    }

    // 4. Send a Message
    public async Task<bool> SendMessageAsync(string recipient, byte[] encryptedContent)
    {
        var response = await _http.PostAsJsonAsync("/send", new
        {
            Recipient = recipient,
            EncryptedContent = encryptedContent
        });
        return response.IsSuccessStatusCode;
    }

    // 5. Check Inbox
    public async Task<List<InboxMessage>> GetInboxAsync()
    {
        try
        {
            return await _http.GetFromJsonAsync<List<InboxMessage>>("/inbox") ?? new List<InboxMessage>();
        }
        catch
        {
            return new List<InboxMessage>();
        }
    }

    // Helper classes for JSON data
    private record LoginResponse(string Token);
    private record PublicKeyResponse(string Key);
    public record InboxMessage(string Sender, byte[] Content, DateTime SentAt);
}