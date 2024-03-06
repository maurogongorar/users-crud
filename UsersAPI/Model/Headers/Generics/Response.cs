namespace UsersAPI.Model.Headers.Generics;

public class Response<T>
{
    public Response(OperationResultEnum operationResult, T result, string errorMessage = null, string userMessage = null)
    {
        this.OperationResult = operationResult;
        this.Result = result;
        this.ErrorMessage = errorMessage;
        this.UserMessage = userMessage;
    }

    public OperationResultEnum OperationResult { get; }

    public T Result { get; }

    public string ErrorMessage { get; }

    public string UserMessage { get; }
}
