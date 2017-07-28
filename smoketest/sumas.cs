using System.Collections.Generic;
using System.Linq;
using System;

class Program
{
    static void Main(string[] args)
    {
        List<int> l = new List<int>();
        foreach (String token in Console.ReadLine().Trim().Split(' ')) {
          l.Add(Int32.Parse(token));
        }
        Console.WriteLine(l.Sum(x => x));
    }
}
