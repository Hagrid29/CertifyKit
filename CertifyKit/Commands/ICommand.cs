using System.Collections.Generic;

namespace CertifyKit.Commands
{
    public interface ICommand
    {
        void Execute(Dictionary<string, string> arguments);
    }
}