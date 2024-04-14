using courses_dotnet_api.Src.DTOs.Account;

namespace courses_dotnet_api.Src.Interfaces;

public interface IAccountRepository
{
    Task<bool> SaveChangesAsync();
    Task AddAccountAsync(RegisterDto registerDto);
    Task<AccountDto?> GetAccountAsync(string email);
    Task<bool> CheckPasswordAsync(string email, string password);
}
