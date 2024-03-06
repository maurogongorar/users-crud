using System;
using System.Runtime.Serialization;

namespace UsersAPI.Exceptions
{
    [Serializable]
    internal class AppException : Exception
    {

        public AppException(string userMessage) : base(userMessage)
        {
            this.UserMessage = userMessage;
        }
        public AppException(string message, string userMessage) : base(message)
        {
            this.UserMessage = userMessage;
        }

        public AppException(string message, string userMessage, Exception innerException) : base(message, innerException)
        {
            this.UserMessage = userMessage;
        }

        protected AppException(string userMessage, SerializationInfo info, StreamingContext context) : base(info, context)
        {
            this.UserMessage = userMessage;
        }

        public string UserMessage { get; }
    }
}