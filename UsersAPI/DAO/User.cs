namespace UsersAPI.DAO;

public class User
{
    public long UserId { get; set; }

    public string Name { get; set; }

    public string Surname { get; set; }

    public string UserName { get; set; }

    public string UserRole { get; set; }

    public bool IsDraw { get; set; } = true;
}
