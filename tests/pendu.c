/*
 * Ugly code, I know... it was one of my first program in C.
 * But the reverse works !
 *
 * The executable is in PE.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void verification(char caract , char mot[] , int lettreTrouvee[] , int donnees[]);
long maj(char caract);

int motAleatoire(char mot[]) {
    // it doesn't matter
    return rand();
}

int main(int argc, char *argv[])
{
    int chance = 10 , chan = 10 ,  menu , *lettreTrouvee = NULL , l , i , a , donnees[2] = {0};
    char mot[100] , caract;
    do
    {
        do
        {
            printf("\n\n              ----------PENDU----------\n\n\n");
            printf("\t\t1 : Jouer\n\t\t2 : Nombre de chance\n\t\t3 : Quitter\n");
            printf("\n\t\t? ");
            scanf("%ld", &menu);
            printf("\n\n");
        } while (menu < 1 || menu > 3);

        if (menu == 1)
        {         
            a = 0;
            mot[100] = motAleatoire(mot);
            l = strlen(mot);
            lettreTrouvee = malloc(l*sizeof(int));
            for(i = 0 ; i < l ; i++)
            {
                lettreTrouvee[i] = 0;
            }
            chance = chan;
            while (a < l && chance > 0)
            {
                printf("Mot secret : ");
                for(i = 0 ; i < l ; i++)
                {
                    if (lettreTrouvee[i] == 1)
                        printf("%c" , mot[i]);
                    else
                        printf("=");
                }
                printf("\nChance(s) : %ld" , chance);
                printf("\nLettre : ");
                do
                {
                    caract = getchar();
                    caract = maj(caract);
                } while (caract == '\n');
                printf("\n");
                donnees[1] = a;
                donnees[2] = chance;
                verification(caract , mot , lettreTrouvee , donnees);
                a = donnees[1];
                chance = donnees[2];
            }
            if (a == l)
            {
                printf("\nVous avez GAGNE :D !!!!!\nLe mot etait bien : %s\n\n", mot);
                chance = chan;
            }
            if (chance == 0 && a != l)
            {
                printf("\nVous avez PERDU  :(\nLe mot etait : %s\n\n", mot);
                chance = chan;
            }
        }

        if (menu == 2)
        {
            do
            {
                printf("\nNombre de chance (defaut : 10 ) ?  ");
                scanf("%ld", &chance);
            } while (chance <= 0);
            chan = chance;
        }
    } while (menu != 3);

    return 0;
}

long maj(char caract)
{
    char maj[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" , min[] = "abcdefghijklmnopqrstuvwxyz";
    int i;
    for(i = 0 ; i < 25 ; i++)
    {
        if (caract == min[i])
            caract = maj[i];
    }
    return caract;
}       

void verification(char caract , char mot[], int lettreTrouvee[] , int donnees[])
{
    int verif = 0 , i;
    for(i = 0 ; i < strlen(mot) ; i++)
    {
        if (caract == mot[i])
        {
            if (lettreTrouvee[i] == 0)
                donnees[1] += 1;  
            lettreTrouvee[i] = 1;
            verif = 1;
        }
    }
    if (verif == 0)
        donnees[2] -= 1;
}
