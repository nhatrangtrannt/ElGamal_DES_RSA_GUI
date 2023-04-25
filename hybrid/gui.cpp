#include<gtk/gtk.h>
#include <iostream>
#include <string>
#include <bitset>
#include "../InfInt/InfInt.h"
#include "../hybrid/DES.h"    
#include "../hybrid/ElGamal.h"                  
using namespace std;



GtkWidget *msglabel, *msgEntry, *signupBtn, *encStartText, *log_text, *bitSizelabel, *bitSizeEntry, *cipherText;
void signup_button_clicked(GtkWidget *wid,gpointer data)
 {    

    const gchar *message = gtk_entry_get_text(GTK_ENTRY(msgEntry)); 
    //gtk_label_set_text(GTK_LABEL(data), message ); 

    const gchar *bitsize = gtk_entry_get_text(GTK_ENTRY(bitSizeEntry)); 

    gtk_entry_set_text(GTK_ENTRY(msgEntry),""); 

    gtk_label_set_text(GTK_LABEL(encStartText), "One-time session key for both parties"); 

    InfInt session_key = el_gamal(stoi(bitsize));
    cout << "\n\nOne-time session key for both parties: " << session_key.toString().c_str() << "\n";

    gtk_label_set_text(GTK_LABEL(log_text), session_key.toString().c_str()); 


 } 
static void activate (GtkApplication* app, gpointer user_data)
 {  


    GtkWidget *window;
    window = gtk_application_window_new (app);
    gtk_window_set_title (GTK_WINDOW (window), "Session Key Generator (Elgamal)");
    gtk_window_set_default_size (GTK_WINDOW (window), 400, 200);
    GtkWidget *showMsg; 
    msglabel = gtk_label_new("Enter your message"); 
    msgEntry = gtk_entry_new(); 

    bitSizelabel = gtk_label_new("Enter a bit size that you want (32, 64, 128, 256, 512, 1024)"); 
    bitSizeEntry = gtk_entry_new(); 



    gtk_entry_set_placeholder_text(GTK_ENTRY(msgEntry),"Message");
    signupBtn = gtk_button_new_with_label("Get Session Key");
    showMsg = gtk_label_new("");
    g_signal_connect(signupBtn,"clicked",G_CALLBACK(signup_button_clicked),showMsg);

    encStartText = gtk_label_new("");
    log_text = gtk_label_new(""); 
    cipherText = gtk_label_new("");
    

    GtkWidget *box; box = gtk_box_new(GTK_ORIENTATION_VERTICAL,20);
    // gtk_box_pack_start(GTK_BOX(box),msglabel,FALSE,FALSE,0);
    // gtk_box_pack_start(GTK_BOX(box),msgEntry,FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(box),bitSizelabel,FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(box),bitSizeEntry,FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(box),signupBtn,FALSE,FALSE,0); 
    gtk_box_pack_start(GTK_BOX(box),showMsg,FALSE,FALSE,0); 
    gtk_box_pack_start(GTK_BOX(box),encStartText,FALSE,FALSE,0); 
    gtk_box_pack_start(GTK_BOX(box),log_text,FALSE,FALSE,0); 
    gtk_box_pack_start(GTK_BOX(box),cipherText,FALSE,FALSE,0);

    gtk_container_add(GTK_CONTAINER(window),box); 
    gtk_widget_show_all (window);
 } 
 int main(int argc,char **argv)
 {
     GtkApplication *app;
     int status;
     app = gtk_application_new ("com.crypto.project", G_APPLICATION_FLAGS_NONE);
     g_signal_connect (app, "activate", G_CALLBACK(activate), NULL);
     status = g_application_run(G_APPLICATION(app), argc, argv);
     g_object_unref (app);
     return status;
 }