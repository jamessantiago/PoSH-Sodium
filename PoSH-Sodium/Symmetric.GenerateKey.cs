using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management.Automation;
using Sodium;

namespace PoSH_Sodium
{
    [Cmdlet(VerbsCommon.New, "Key")]
    public class GenerateKey : PSCmdlet
    {        
        protected override void ProcessRecord()
        {
            var key = new SodiumSymmetricKey()
            {
                KeyType = "Symmetric",
                Key = SecretBox.GenerateKey().ToBase64String()
            };
            WriteObject(key);
        }
    }
}
