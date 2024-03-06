using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UsersAPI.DAO;

namespace UsersAPI.DAL
{
    public interface IUsersService : IDisposable
    {
        (string, DateTime) Authenticate(string userName, string password);

        int ChangePaassword(string userName, string password);

        int DeleteUser(long userId);

        long InsertUser(User user);

        User GetUserById(long userId);

        IEnumerable<User> GetUsers(string name = "");

        int UpdateUser(User user);
    }
}
