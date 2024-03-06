namespace UsersAPI.Authentication;

public interface IJwtAuthentication
{
    (string, DateTime) GetToken(string userName, IEnumerable<string> roles);
}
