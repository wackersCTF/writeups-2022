#include <iostream>
#include <string>
using namespace std;
int main() {    
    int n; cin >> n;
    
    int counter = 0;
    int column[4] = {0, 0, 0, 0};
    for (int i = 0; i <= n; i++)
    {
        string line1; getline(cin, line1);
        for (int j = 0; j < line1.size(); j++) {
            if (line1[j] == '-')
            {
                counter++;
            }
            else if (line1[j] == '#') {
                column[j-1]++;
            }
            if (column[j-1] > 0 && line1[j] == '-') {
                counter--;
                column[j-1] = 0;
            }
            
    }

    }
    cout << counter;
}
SEKAI{wysi_Wh3n_y0u_fuxx1ng_C_727727}
