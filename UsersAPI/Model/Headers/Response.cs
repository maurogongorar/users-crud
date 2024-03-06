using UsersAPI.Model.Headers.Generics;

namespace UsersAPI.Model.Headers
{
    public class Response : Response<object>
    {
        public Response(OperationResultEnum operationResult, object result, string errorMessage = null,
            string userMessage = null) : base(operationResult, result, errorMessage, userMessage)
        { }
    }
}
