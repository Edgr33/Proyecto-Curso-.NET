using System.Text;

namespace EvaluacionEduardoGomezMVC.Helpers
{
    public static class IdHelper
    {
        public static string GenerateCustomerId(string companyName)
        {
            // Get a hash of the company name
            int hash = companyName.GetHashCode();

            // Convert to a positive number if needed
            hash = Math.Abs(hash);

            // Convert to base 36
            string base36 = ConvertToBase36(hash);

            // Pad or truncate to 5 characters
            if (base36.Length > 5)
            {
                base36 = base36.Substring(0, 5);
            }
            else if (base36.Length < 5)
            {
                base36 = base36.PadRight(5, 'X');
            }

            return base36;
        }

        private static string ConvertToBase36(int input)
        {
            const string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            StringBuilder result = new StringBuilder();

            while (input > 0)
            {
                result.Insert(0, chars[input % 36]);
                input /= 36;
            }

            return result.ToString();
        }
    }
}

