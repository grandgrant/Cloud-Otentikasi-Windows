using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.SqlClient;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WindowsFormsApplication1
{
    public partial class Form2 : Form
    {
        string[] projectNumber;
        string[] projectId;
        string[] lifecycleState;
        string[] projectName;
        string[] createTime;

        public Form2(string[] data1, string[] data2, string[] data3, string[] data4, string[] data5)
        {
            InitializeComponent();
            addData(data4);
            projectNumber = data1;
            projectId = data2;
            lifecycleState = data3;
            projectName = data4;
            createTime = data5;
        }
        
        


        public void addData(string[] data4)
        {
            for (int i=0;i<data4.Length;i++)
            {
                listBox1.Items.Add(data4[i]);
            }
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            for (int i = 0; i < projectName.Length; i++)
            {
                if (projectName[i] == listBox1.GetItemText(listBox1.SelectedItem))
                {
                    label2.Text = "Nomor Proyek : " + projectNumber[i];
                    label3.Text = "Identitas Proyek : " + projectId[i];
                    label4.Text = "Status Proyek : " + lifecycleState[i];
                    label5.Text = "Nama Proyek : " + projectName[i];
                    label6.Text = "Waktu Proyek dibuat : " + createTime[i];
                }
            }
        }

       
    }
}
