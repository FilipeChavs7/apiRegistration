using IdentityModel.Client;
using System.Threading.Tasks;

namespace WebApi.Services
{
    public interface ITokenService
    {
        Task<TokenResponse> GetToken(string scope);
    }
}