#include <iostream>
#include <fstream>
#include <iomanip>
#include <windows.h>
#include <string>
#include <vector>
#include <io.h>
//SW_SHOW
typedef unsigned char uchar;
using namespace std;
typedef unsigned (__stdcall * pICFUNC)(const char *, int);
typedef unsigned (__stdcall * pIFUNC)(int);
typedef unsigned (__stdcall * pIIFUNC)(int,int );
struct FileHead
{
    char name[12]; //@0
    char sth1[4];  //@12
    WORD flags;    //@16
    WORD number;//char code[2]; //number? @18
    DWORD size1;//char sth2[4]; //@20
    DWORD dataptr;//4 //@24
    DWORD size2;//4 //@28
    FileHead()
    {
        memset(this,0,sizeof(this));
    }
};
struct tfile
{
    char* buf;
    unsigned size;
    string name;
    int flags;
    char* header;
    tfile()
    {
    };
    tfile(char* ibuf,unsigned isize,string iname)
    {
        buf=ibuf;
        size=isize;
        name=iname;
    }
};
typedef vector <tfile> tfiles;
struct Lib//size 56
{
    char sig[4];
    unsigned char rescount;
    char sth[51];

};

void Encode(BYTE code1,BYTE code2,BYTE *buf,size_t size)
{

    for (int i=0;i<size;i++)
    {
        code1=code2^ (2*code1);
        code2 = code1 ^ (BYTE)((BYTE)code2 >> 1);
        buf[i]=buf[i]^code1;
    }
}
void ExtractHeaders(string file)
{
    fstream inp(file.c_str(),fstream::in|fstream::binary);
    fstream dump("headers.lib",fstream::out|fstream::binary|fstream::trunc);
    inp.seekg(4, ios::beg);
    unsigned int size=0;
    inp.read((char*)&size,2);
    struct Ss
    {
        BYTE c1;
        BYTE c2;
    }test;
    inp.seekg(20, ios::beg);
    inp.read((char*)&test,sizeof(Ss));
    //for(int i=0;i<25;out.i++)
    //{
    //inp.read((char*)&c1,1);
    //inp.read((char*)&c2,1);
    //}
    //std::cout<<sizeof(FileHead)<<std::endl;
    inp.seekg(32, ios::beg);
    char *buf;
    FileHead *ff;

    buf=new char[size*32];
    ff=(FileHead*)buf;
    inp.read((char*)buf,size*32);
    Encode(test.c1,test.c2,(BYTE*)buf,size*32);
    dump.write((char*)buf,size*32);
    for (int i=0;i<size;i++)
    {
        cout<<ff[i].name<<" "<<ff[i].size1<<"->"<<ff[i].size2<<endl;
    }
    delete [] buf;
}
class saverLib
{

public:
    tfiles files;
    void AddDir(string dir)
    {
        WIN32_FIND_DATA FindFileData;
        HANDLE hFind;
        string ddir;
        ddir=dir;
        ddir+="\\\*";
        hFind = FindFirstFile(ddir.c_str(),&FindFileData);
        if (hFind == INVALID_HANDLE_VALUE)
            return;
        while (hFind!=INVALID_HANDLE_VALUE)
        {
            fstream inp;

            cout<<"Found:"<<FindFileData.cFileName<<endl;
            if (FindFileData.dwFileAttributes != FILE_ATTRIBUTE_DIRECTORY)
            {
                string fdir;
                fdir=dir;
                fdir+="\\";
                fdir+=FindFileData.cFileName;
                inp.open(fdir.c_str(),fstream::in|fstream::binary);
                inp.seekg(0,ios::end);
                long pos=inp.tellg();
                inp.seekg(0,ios::beg);
                char *buf=new char[pos];
                inp.read(buf,pos);
                tfile f;
                f.buf=buf;
                f.size=pos;
                f.name=FindFileData.cFileName;//FindFileData.cAlternateFileName;
                files.push_back(f);
                inp.close();
                cout<<"done adding "<<FindFileData.cFileName<<endl;
            }
            if (!FindNextFile(hFind,&FindFileData))
                return;
        }

    }
    void Save(string file)
    {
        fstream dump(file.c_str(),fstream::out|fstream::binary|fstream::trunc);
        //Lib a;
        char sig[4]={'N','L',0,1};
        //a.rescount=files.size();
        unsigned int count=files.size();
        //dump.write((char*)&a,sizeof(Lib));
        dump.write(sig,4);
        dump.write((char*)&count,2);
        dump.write((char*)&count,2);

        //dump<<(int)0;
        dump.seekp(14,ios::beg);
        dump<<'\xBA'<<'\xAB';//<<'\xef'<<'\x35';//?

        dump.seekp(20,ios::beg);
        dump<<(char)'\0';
        dump<<(char)'\0';
        dump.seekp(32,ios::beg);
        for (int i=0;i<files.size();i++)
        {
            FileHead h;
            strcpy(h.name,files[i].name.c_str());
            h.flags=0; //or =32 if only encoded
            h.number=i;
            h.size1=files[i].size;
            h.size2=files[i].size;
            h.dataptr=0;
            dump.write((char*)&h,sizeof(h));
        }
        for (int i=0;i<files.size();i++)
        {
            long cpos=dump.tellp();
            dump.write(files[i].buf,files[i].size);
            //long pos;
            //pos=dump.tellp();
            dump.seekp(32*(i+1)+24,ios::beg);
            dump.write((char*)&cpos,sizeof(cpos));
            dump.seekp(0,ios::end);
        }
    }
};
class parkanLib
{
public:
    tfiles myfiles;
private:
    unsigned libhndl;
    HINSTANCE DLL;
    pICFUNC OpenLib;
    pIFUNC CloseLib;
    pIIFUNC LoadLib;
    pIIFUNC GetPackMethod;
    pIIFUNC GetState;
    int lload;
    unsigned char ResCount;
    string libname;
public:
    int getflags(int resnum)
    {
        return *((int*)(gethead(resnum)+8));
    }
    unsigned getsize(int resnum)
    {
        return *((unsigned*)(((char*)libhndl)+resnum*64+80));
    }
    char* gethead(int resnum)
    {
        return (char*)libhndl+resnum*64+56;
    }
    string getname(int resnum)
    {
        /*int i=0;
        while(((char*)libhndl)[resnum*64+56+i]!=0)
            i++;*/
        return string(gethead(resnum));

    }
    unsigned getpointer(int resnum)
    {
        return *((unsigned *)(gethead(resnum)+48));
    }

    unsigned getpackmet(int resnum)
    {
        return GetPackMethod(libhndl,resnum);
    }
    parkanLib(const char*  fname,int flags)
    {
        libname=fname;
        DLL=LoadLibrary("ngi32.dll");

        FARPROC lpfnGetProcessID = GetProcAddress(HMODULE
                                   (DLL), "rsOpenLib");
        OpenLib = pICFUNC(lpfnGetProcessID);

        lpfnGetProcessID = GetProcAddress(HMODULE
                                          (DLL), "rsCloseLib");
        CloseLib= pIFUNC(lpfnGetProcessID);

        lpfnGetProcessID = GetProcAddress(HMODULE
                                          (DLL), "rsLoad");
        LoadLib=pIIFUNC(lpfnGetProcessID);

        lpfnGetProcessID = GetProcAddress(HMODULE
                                          (DLL), "rsGetPackMethod");
        GetPackMethod=pIIFUNC(lpfnGetProcessID);

        lpfnGetProcessID = GetProcAddress(HMODULE
                                          (DLL), "rsModuleState");
        GetState=pIIFUNC(lpfnGetProcessID);

        //int __stdcall rsModuleState(int a1, int a2)
        libhndl=OpenLib(fname,flags);
        /*char *ttt=new char[1000];
        for(int o=0;o<1000;o++)
        ttt[o]='A';
        */
        ResCount=((char*)libhndl)[4];
        cout <<"rc:"<<(int)ResCount<<endl;
        /*fstream dump("dump1.bin",fstream::out);
        for(unsigned i=0;i<4792;i++)
        {
        cout<<i<<endl;
        char a=((char*)libhndl)[i];
        dump<<a;
        }*/

        //cout<<vf<<endl;
        //int lastl=0;

        for (int i=0;i<ResCount;i++)
        {
            lload=LoadLib(libhndl,i);
            cout<<GetState(libhndl,i)<<"->";
            myfiles.push_back(tfile((char*)lload,getsize(i),getname(i)));
            myfiles[i].header=(char*)(libhndl+64*i+56);
            myfiles[i].flags=getflags(i);
            //FileSthInLib = LibPtr + 64 * resnum + 56;
            cout<<myfiles[i].name<<" size:"<<myfiles[i].size<<" "<<getpackmet(i)<<" "<<GetState(libhndl,i)<<endl;//myfiles[i].flags<<endl;
            //cout<<myfiles[i].buf<<endl;
            //cout<<"i->"<< setw(4) <<i<<" "<<"libhndl: "<<libhndl<<" "<<lload<<" "<<getpointer(i)<<" diff: "<< setw(8) <<lload-lastl;
            //cout<<" size:"<<getsize(i)<<endl;
            //lastl=lload;
            //cout<<((int*)lload+i)[0]<<endl;
        }

        /*fstream dump2("dump2.bin",fstream::out);
        for(unsigned i=0;i<ResCount;i++)
        {
        //cout<<i<<endl;
        /*for(int o=0;o<64;o++)
        {
        char a=((char*)libhndl)[i*64+56+o];
        cout<<a;
        }
        cout<<endl;
        cout<<getname(i)<<endl;
        }*/
        //delete [] ttt;
    }
    void SaveFile(int res,string name="")
    {
        string tname;
        if (name=="")
        {
            string sname=libname.substr(0,libname.size()-4);
            mkdir(sname.c_str());
            tname+=sname+"\\";
            tname+=myfiles[res].name;
        }
        else
            tname=name;
        //tname=libname;

            //tname="out\\"+tname;

        fstream dump(tname.c_str(),fstream::out|fstream::binary|fstream::trunc);
        dump.write(myfiles[res].buf,myfiles[res].size);
        //char *buf=myfiles[res].buf;
        /*for (unsigned i=0;i<myfiles[res].size;i++)
        {
            dump<<buf[i];
        }*/
    }
    int FileCount()
    {
        return myfiles.size();
    }
    ~parkanLib()
    {
        CloseLib(libhndl);
        FreeLibrary(DLL);
    }
} *mainlib;

void usage(char *name)
{
    cout<<"Usage:"<<name<<" <libname>"<<endl;
    cout<<"extracts all files from lib to out\\*.*"<<endl;

}
int main(int argc,char *argv[])
{
    /*cout << "Parkan lib extractor" << endl;
    if(argc<2)
        {
        usage(argv[0]);
        return -1;
        }
    mainlib=new parkanLib(argv[1],0);*/
    //ExtractHeaders("tools.lib");
    /*saverLib ll1;
    tfile tf;
    tf.name="HOLA.NGA";
    tf.buf="TENTENTEN!";
    tf.size=10;
    ll1.files.push_back(tf);

    ll1.Save("test.lib");*/
    //return 0;

    size_t s=0;
    string a;
    cin>>a;
    if (a.substr(0,1)=="!")
    {
        saverLib ll;
        ll.AddDir(a.substr(1));
        ll.Save(a.substr(1)+".LIB_NEW");//"out.lib");
    }
    else
    {
        if (a.substr(0,1)=="@")
        {
            ExtractHeaders(a.substr(1));
        }
        else
        {
            mainlib=new parkanLib(a.c_str(),1);
            for (int i=0;i<mainlib->FileCount();i++)
            {
                s+=mainlib->myfiles[i].size;
                mainlib->SaveFile(i);
            }
            std::cout<<s<<std::endl;
            delete mainlib;
        }
        return 0;

    }
}
