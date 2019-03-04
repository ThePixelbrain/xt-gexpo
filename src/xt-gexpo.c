/*
    Griffeye XML export X-Tension for X-Ways Forensics
    Copyright (C) 2019 R. Yushaev

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <datetimeapi.h>
#include <PathCch.h>
#define STRICT_TYPED_ITEMIDS
#include <Shlobj.h>
#include <strsafe.h>

#define EXPORT_DIR  L"Griffeye export"
#define REP_TABLE   L"[XT] Exported by xt-gexpo"
#define IMG_SUBDIR  L"Pictures"
#define VID_SUBDIR  L"Movies"
#define CASE_REPORT L"Case Report.xml"
#define IMG_REPORT  L"C4P Index.xml"
#define VID_REPORT  L"C4M Index.xml"
#define MIN_VER     1760
#define MIN_VER_S   "17.6"

#define NAME_BUF_LEN 256

#define TYPE_OTHER   0
#define TYPE_PICTURE 1
#define TYPE_VIDEO   2

#define EXPORT __declspec (dllexport)

// Converts WinAPI FILETIME to unix epoch time
#define GET_ITEM_TIME(x) (XWF_GetItemInfo (nItemID, (x), NULL) / 10000000 \
                          - 11644473600LL)

struct XtFile
{
    INT64 id;
    INT64 created;
    INT64 accessed;
    INT64 written;
    INT64 filesize;

    WCHAR fullpath[MAX_PATH];
};

// Decoupled report data
// In case of a merged report, all XtVolumes will point to the same XtReport,
// increasing its ref_count. In case of separate reports per evidence item,
// each XtVolume has its own XtReport.
struct XtReport
{
    UINT32 ref_count;

    UINT32 image_count;
    UINT32 movie_count;

    HANDLE xml_case_report;
    HANDLE xml_image_index;
    HANDLE xml_movie_index;

    WCHAR export_path[MAX_PATH];
};

struct XtVolume
{
    struct XtVolume * next;
    struct XtReport * report;

    // Top-level evidence item name
    // Used to group volumes (partitions) together
    WCHAR name[NAME_BUF_LEN];

    // Evidence item + current volume (partition)
    // Used in the <fullpath> tags of file indexes
    WCHAR name_ex[NAME_BUF_LEN];
};

struct XtVolume * first_volume   = NULL;
struct XtVolume * current_volume = NULL;

WCHAR case_name[NAME_BUF_LEN] = { 0 };
WCHAR export_dir[MAX_PATH]    = { 0 };

int split_evidence_items = 0;
int xwf_version = 0;

// X-Tension API
// https://www.x-ways.net/forensics/x-tensions/api.html

#define XTAPI __stdcall

#define XT_ACTION_RUN 0
#define XT_ACTION_RVS 1
#define XT_ACTION_LSS 2
#define XT_ACTION_PSS 3
#define XT_ACTION_DBC 4
#define XT_ACTION_SHC 5

#define XT_INIT_XWF        0x00000001
#define XT_INIT_WHX        0x00000002
#define XT_INIT_XWI        0x00000004
#define XT_INIT_BETA       0x00000008
#define XT_INIT_QUICKCHECK 0x00000020
#define XT_INIT_ABOUTONLY  0x00000040

#define XT_PREPARE_CALLPI     0x01
#define XT_PREPARE_CALLPILATE 0x02

#define XWF_ITEM_INFO_CREATIONTIME     32
#define XWF_ITEM_INFO_MODIFICATIONTIME 33
#define XWF_ITEM_INFO_LASTACCESSTIME   34

#define XWF_CASEPROP_TITLE 1
#define XWF_CASEPROP_DIR   6

typedef LONG   (XTAPI * fptr00) (LONG, LPWSTR, DWORD);
typedef INT64  (XTAPI * fptr01) (LPVOID, LONG, PVOID, LONG);
typedef HANDLE (XTAPI * fptr02) (LPVOID);
typedef INT64  (XTAPI * fptr03) (LONG, LONG, LPBOOL);
typedef LPWSTR (XTAPI * fptr04) (LONG);
typedef LONG   (XTAPI * fptr05) (LONG);
typedef INT64  (XTAPI * fptr06) (LONG);
typedef LONG   (XTAPI * fptr07) (LONG, LPWSTR, DWORD);
typedef HANDLE (XTAPI * fptr08) (HANDLE, LPVOID);
typedef VOID   (XTAPI * fptr09) (HANDLE, LPWSTR, DWORD);
typedef void   (XTAPI * fptr10) (LPWSTR, DWORD);
typedef DWORD  (XTAPI * fptr11) (HANDLE, INT64, LPVOID, DWORD);

fptr00 XWF_AddToRepTable = NULL;
fptr01 XWF_GetCaseProp   = NULL;
fptr02 XWF_GetFirstEvObj = NULL;
fptr03 XWF_GetItemInfo   = NULL;
fptr04 XWF_GetItemName   = NULL;
fptr05 XWF_GetItemParent = NULL;
fptr06 XWF_GetItemSize   = NULL;
fptr07 XWF_GetItemType   = NULL;
fptr08 XWF_GetNextEvObj  = NULL;
fptr09 XWF_GetVolumeName = NULL;
fptr10 XWF_OutputMessage = NULL;
fptr11 XWF_Read          = NULL;

VOID
GetXwfFunctions ()
{
    HMODULE h = GetModuleHandleW (NULL);

    XWF_AddToRepTable = (fptr00) GetProcAddress (h, "XWF_AddToReportTable");
    XWF_GetCaseProp   = (fptr01) GetProcAddress (h, "XWF_GetCaseProp");
    XWF_GetFirstEvObj = (fptr02) GetProcAddress (h, "XWF_GetFirstEvObj");
    XWF_GetItemInfo   = (fptr03) GetProcAddress (h, "XWF_GetItemInformation");
    XWF_GetItemName   = (fptr04) GetProcAddress (h, "XWF_GetItemName");
    XWF_GetItemParent = (fptr05) GetProcAddress (h, "XWF_GetItemParent");
    XWF_GetItemSize   = (fptr06) GetProcAddress (h, "XWF_GetItemSize");
    XWF_GetItemType   = (fptr07) GetProcAddress (h, "XWF_GetItemType");
    XWF_GetNextEvObj  = (fptr08) GetProcAddress (h, "XWF_GetNextEvObj");
    XWF_GetVolumeName = (fptr09) GetProcAddress (h, "XWF_GetVolumeName");
    XWF_OutputMessage = (fptr10) GetProcAddress (h, "XWF_OutputMessage");
    XWF_Read          = (fptr11) GetProcAddress (h, "XWF_Read");
}

// Returns 1 if all function pointers have been initialized
// Returns 0 if at least one function pointer is NULL
DWORD
CheckXwfFunctions ()
{
    return (XWF_AddToRepTable
         && XWF_GetCaseProp
         && XWF_GetFirstEvObj
         && XWF_GetItemInfo
         && XWF_GetItemName
         && XWF_GetItemParent
         && XWF_GetItemSize
         && XWF_GetItemType
         && XWF_GetNextEvObj
         && XWF_GetVolumeName
         && XWF_OutputMessage
         && XWF_Read) ? 1 : 0;
}

// Expands provided path on dialog initialization
BFFCALLBACK MyCallback (HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)
{
    if (BFFM_INITIALIZED == uMsg)
    {
       SendMessageW (hwnd, BFFM_SETEXPANDED, TRUE, lpData);
    }
    return 0;
}

// Opens open file dialog, saves folder path in dir
// Returns 1 if the user selected a writeable directory
// Returns 0 if not
BOOL
BrowseForExportDir (LPWSTR dir)
{
    // Should be already initialized
    OleInitialize (NULL);

    BROWSEINFOW bi = { 0 };

    bi.lpszTitle = L"Griffeye XML export X-Tension\n\n"
                    "Please select the target directory:";
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_USENEWUI;
    // Use MyCallback to preselect and expand dir
    bi.lpfn      = (BFFCALLBACK) MyCallback;
    bi.lParam    = (LPARAM) dir;

    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW (&bi);
    if (NULL == pidl)
    {
        export_dir[0] = L'\0';
        return 0;
    }

    // Store actual directory path inside dir
    SHGetPathFromIDListW (pidl, dir);
    CoTaskMemFree (pidl);

    // Recursively prompt until we can create the export directory at the
    // selected path.
    PWSTR new_dir = NULL;
    PathAllocCombine (dir, EXPORT_DIR, 0, &new_dir);
    if (!CreateDirectoryW (new_dir, NULL))
    {
        LocalFree (new_dir);

        if (ERROR_ALREADY_EXISTS == GetLastError ())
        {
            MessageBoxW (NULL,
                         L"The selected directory already contains a Griffeye"
                          " export folder. Plese select another directory.",
                         L"Notice",
                         MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxW (NULL,
                         L"Could not create the Griffeye export folder here. "
                          "Please select another directory",
                         L"Error",
                         MB_ICONERROR);
        }
        return BrowseForExportDir (dir);
    }

    StringCchCopyW (dir, MAX_PATH, new_dir);

    LocalFree (new_dir);

    return 1;
}

// Returns 1 if the XtVolume was found.
// Returns 0 if a new XtVolume was created.
BOOL
SetCurrentVolume (LPWSTR name)
{
    struct XtVolume * previous = first_volume;
    struct XtVolume * current  = previous;

    while (current)
    {
        if (0 == wcscmp (name, current->name))
        {
            current_volume = current;
            return 1;
        }
        previous = current;
        current  = current->next;
    }

    // We need to create a new (maybe first) volume
    current_volume = calloc (1, sizeof (struct XtVolume));
    if (previous)
    {
        previous->next = current_volume;
    }
    else
    {
        first_volume = current_volume;
    }

    return 0;
}

HANDLE
MyCreateFile (LPCWSTR lpFileName)
{
    return CreateFileW (lpFileName,
                        GENERIC_WRITE,
                        0,
                        NULL,
                        CREATE_NEW,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
}

// Copies a file from X-Ways to specified export_path
BOOL
ExportXwfFile (HANDLE hItem, LPCWSTR export_path, INT64 size)
{
    HANDLE file = MyCreateFile (export_path);
    if (INVALID_HANDLE_VALUE == file)
    {
        return 0;
    }

    LPVOID filebuf  = (LPVOID) malloc (size);
    if (!filebuf)
    {
        CloseHandle (file);
        return 0;
    }

    XWF_Read (hItem, 0, filebuf, size);

    BOOL rv = WriteFile (file, filebuf, size, NULL, NULL);

    CloseHandle (file);
    free (filebuf);

    return rv;
}

BOOL
XmlWriteString (HANDLE file, LPCWSTR str)
{
    return WriteFile (file, str, sizeof (WCHAR) * wcslen (str), NULL, NULL);
}

BOOL
XmlWriteBomHeader (HANDLE file)
{
    char bom[2] = { 0xff, 0xfe };
    LPCWSTR header = L"<?xml version=\"1.0\" encoding=\"utf-16\"?>\r\n";

    return (WriteFile (file, bom, 2, NULL, NULL)
            && XmlWriteString (file, header));
}

BOOL
XmlWriteReport (HANDLE file)
{
    WCHAR ver[18]  = { 0 };
    WCHAR date[64] = { 0 };
    WCHAR time[64] = { 0 };

    StringCchPrintfW (ver, 18, L"%d.%d",
                      xwf_version / 100,
                      xwf_version % 100 / 10);
    GetDateFormatEx (LOCALE_NAME_USER_DEFAULT,
                     0, NULL,
                     L"dd'-'MMM'-'yyyy",
                     date, 64, NULL);
    GetTimeFormatEx (LOCALE_NAME_USER_DEFAULT,
                     TIME_FORCE24HOURFORMAT, NULL,
                     L"HH'-'mm'-'ss",
                     time, 64);

    return (XmlWriteBomHeader (file)
            && XmlWriteString (file, L"<CaseReport>\r\n  <CaseNumber><![CDATA"
                                      "[")
            && XmlWriteString (file, case_name)
            && XmlWriteString (file, L"]]></CaseNumber>\r\n  <Date><![CDATA[")
            && XmlWriteString (file, date)
            && XmlWriteString (file, L"]]></Date>\r\n  <Time><![CDATA[")
            && XmlWriteString (file, time)
            && XmlWriteString (file, L"]]></Time>\r\n  <Comment><![CDATA[Crea"
                                      "ted by Griffeye XML export X-Tension: "
                                      "https://github.com/Naufragous/xt-gexpo"
                                      "/ ]]></Comment>\r\n  <DLLversion><![CD"
                                      "ATA[V1.0]]></DLLversion>\r\n  <XwaysVe"
                                      "rsion><![CDATA[")
            && XmlWriteString (file, ver)
            && XmlWriteString (file, L"]]></XwaysVersion>\r\n</CaseReport>"));
}

BOOL
XmlWriteIndex (HANDLE file)
{
    LPCWSTR s = L"<ReportIndex version=\"1.0\" source=\"Naufragous\" dll=\"Gr"
                 "iffeye XML export X-Tension\">\r\n";

    return (XmlWriteBomHeader (file)
            && XmlWriteString (file, s));
}

// Appends a complete file entry to specified index file
BOOL
XmlWriteXtFile (HANDLE file, struct XtFile * xf,
                LPCWSTR tag1, LPCWSTR tag2, LPCWSTR subdir)
{
    WCHAR id[32]    = { 0 };
    WCHAR ctime[32] = { 0 };
    WCHAR atime[32] = { 0 };
    WCHAR wtime[32] = { 0 };
    WCHAR size[32]  = { 0 };

    StringCchPrintfW (id,    32, L"%lld", xf->id);
    StringCchPrintfW (ctime, 32, L"%lld", xf->created);
    StringCchPrintfW (atime, 32, L"%lld", xf->accessed);
    StringCchPrintfW (wtime, 32, L"%lld", xf->written);
    StringCchPrintfW (size,  32, L"%lld", xf->filesize);

    return (   XmlWriteString (file, L"<")
            && XmlWriteString (file, tag1)
            && XmlWriteString (file, L">\r\n  <path><![CDATA[")
            && XmlWriteString (file, subdir)
            && XmlWriteString (file, L"\\]]></path>\r\n  <")
            && XmlWriteString (file, tag2)
            && XmlWriteString (file, L">")
            && XmlWriteString (file, id)
            && XmlWriteString (file, L"</")
            && XmlWriteString (file, tag2)
            && XmlWriteString (file, L">\r\n  <id>")
            && XmlWriteString (file, id)
            && XmlWriteString (file, L"</id>\r\n  <category>0</category>\r\n "
                                      " <fileoffset>0</fileoffset>\r\n  <full"
                                      "path><![CDATA[")
            && XmlWriteString (file, xf->fullpath)
            && XmlWriteString (file, L"]]></fullpath>\r\n  <created>")
            && XmlWriteString (file, ctime)
            && XmlWriteString (file, L"</created>\r\n  <accessed>")
            && XmlWriteString (file, atime)
            && XmlWriteString (file, L"</accessed>\r\n  <written>")
            && XmlWriteString (file, wtime)
            && XmlWriteString (file, L"</written>\r\n  <fileSize>")
            && XmlWriteString (file, size)
            && XmlWriteString (file, L"</fileSize>\r\n</")
            && XmlWriteString (file, tag1)
            && XmlWriteString (file, L">\r\n"));
}

// Creates templates for the three xml report files in dir and also
// subdirectories for images and videos.
// Returns 1 if all directories and files were created
// Returns 0 otherwise
BOOL
XmlCreateReportFiles (LPCWSTR dir)
{
    PWSTR volume_dir  = NULL;
    PWSTR img_subdir  = NULL;
    PWSTR vid_subdir  = NULL;
    PWSTR case_report = NULL;
    PWSTR image_index = NULL;
    PWSTR movie_index = NULL;

    PathAllocCombine (dir, IMG_SUBDIR,  0, &img_subdir);
    PathAllocCombine (dir, VID_SUBDIR,  0, &vid_subdir);
    PathAllocCombine (dir, CASE_REPORT, 0, &case_report);
    PathAllocCombine (dir, IMG_REPORT,  0, &image_index);
    PathAllocCombine (dir, VID_REPORT,  0, &movie_index);

    CreateDirectoryW (dir, NULL);
    CreateDirectoryW (img_subdir, NULL);
    CreateDirectoryW (vid_subdir, NULL);

    current_volume->report = calloc (1, sizeof (struct XtReport));
    current_volume->report->ref_count = 1;
    current_volume->report->xml_case_report = MyCreateFile (case_report);
    current_volume->report->xml_image_index = MyCreateFile (image_index);
    current_volume->report->xml_movie_index = MyCreateFile (movie_index);
    StringCchCopyW (current_volume->report->export_path, MAX_PATH, dir);

    LocalFree (img_subdir);
    LocalFree (vid_subdir);
    LocalFree (case_report);
    LocalFree (image_index);
    LocalFree (movie_index);

    if (INVALID_HANDLE_VALUE == current_volume->report->xml_case_report
     || INVALID_HANDLE_VALUE == current_volume->report->xml_image_index
     || INVALID_HANDLE_VALUE == current_volume->report->xml_movie_index)
    {
        return 0;
    }

    XmlWriteReport (current_volume->report->xml_case_report);
    XmlWriteIndex  (current_volume->report->xml_image_index);
    XmlWriteIndex  (current_volume->report->xml_movie_index);

    return 1;
}

BOOL
XmlAppendImage (struct XtFile * xf)
{
    return XmlWriteXtFile (current_volume->report->xml_image_index, xf,
                        L"Image", L"picture", IMG_SUBDIR);
}

BOOL
XmlAppendMovie (struct XtFile * xf)
{
    return XmlWriteXtFile (current_volume->report->xml_movie_index, xf,
                        L"Movie", L"movie", VID_SUBDIR);
}

// Executed once before processing
EXPORT LONG XTAPI
XT_Init (DWORD nVersion, DWORD nFlags, HANDLE hMainWnd, void* LicInfo)
{
    // Support X-Ways Forensics only
    // No support for WinHex, Investigator and beta versions
    if (0 == (XT_INIT_XWF & nFlags)
     || XT_INIT_WHX  & nFlags
     || XT_INIT_XWI  & nFlags
     || XT_INIT_BETA & nFlags)
    {
        return -1;
    }

    // Do not need to load anything for those calls
    if (XT_INIT_ABOUTONLY  & nFlags
     || XT_INIT_QUICKCHECK & nFlags)
    {
        return 1;
    }

    GetXwfFunctions ();
    if (!CheckXwfFunctions ())
    {
        return -1;
    }

    // From here on we always return 1, even when an error occurs.
    // Returning -1 would provoke additional error messages in X-Ways
    // which suggest that the X-Tension is not working properly.
    // We will check export_dir variable instead and abort silently
    // later on in XT_Prepare or XT_ProcessItemEx, if necessary.

    xwf_version = nVersion >> 16;
    if (MIN_VER > xwf_version)
    {
        XWF_OutputMessage (L"NOTICE: Griffeye XML export X-Tension supports X"
                            "-Ways Forensics version "MIN_VER_S" or later onl"
                            "y. Aborting.", 2);
        return 1;
    }

    // Get case name for our Case Report.xml
    // Also check if we have any case at all
    if (-1 == XWF_GetCaseProp (NULL, XWF_CASEPROP_TITLE,
                               case_name, NAME_BUF_LEN))
    {
        XWF_OutputMessage (L"NOTICE: Griffeye XML export X-Tension needs an a"
                            "ctive case. Aborting.", 2);
        return 1;
    }
    // Filter out any ]] to prevent XML errors
    for (int i = 0; i < (wcslen (case_name) - 1); i++)
    {
        if (L']' == case_name[i] && L']' == case_name[i + 1])
        {
            case_name[i] = L'_';
        }
    }

    // Show 'select folder' dialog, starting at case directory
    XWF_GetCaseProp (NULL, XWF_CASEPROP_DIR, export_dir, MAX_PATH);
    if (0 == BrowseForExportDir (export_dir))
    {
        XWF_OutputMessage (L"NOTICE: Griffeye XML export X-Tension needs a va"
                            "lid export directory. Aborting.", 2);
        return 1;
    }

    // If there is more than one evidence item, ask the user whether we should
    // split exported files and create a subdirectory for every evidence item.
    HANDLE first_obj = XWF_GetFirstEvObj (NULL);
    if (first_obj && XWF_GetNextEvObj (first_obj, NULL))
    {
        LPCWSTR cap = L"Do you want a merged export?";
        LPCWSTR msg = L"This case contains several evidence items. Griffeye X"
                       "ML export X-Tension can either create separate export"
                       "s for each evidence item or one export with files fro"
                       "m all evidence items. In any case, the file path will"
                       " include the name of the evidence item and volume.\n "
                       "\nDo you want to merge all exports into one?";
        if (IDNO == MessageBoxW (NULL, msg, cap, MB_YESNO | MB_ICONINFORMATION))
        {
            split_evidence_items = 1;
        }
        else
        {
            // Our first volume will be a dummy one and will just serve as a
            // link to the global XtReport structure.
            current_volume = calloc (1, sizeof (struct XtVolume));
            first_volume   = current_volume;

            if (0 == XmlCreateReportFiles (export_dir))
            {
                XWF_OutputMessage (L"ERROR: Griffeye XML export X-Tension cou"
                                    "ld not create a file. Aborting.", 2);
                export_dir[0] = L'\0';
                return 1;
            }
        }
    }

    XWF_OutputMessage (L"Griffeye XML export X-Tension loaded.", 2);

    // 1: We are NOT thread-safe
    return 1;
}

// Called before each volume (e.g. every partition of a hard drive)
EXPORT LONG XTAPI
XT_Prepare (HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, PVOID lpReserved)
{
    LONG return_value = 0;

    switch (nOpType)
    {
    case XT_ACTION_RUN:
        // We could call XWF_GetVolumeInformation and check if we have
        // a volume we could work on, but this is so much simpler.
        XWF_OutputMessage (L"NOTICE: Griffeye XML export X-Tension is not sup"
                            "posed to be executed from the Tools menu. Please"
                            " start the X-Tension from the directory browser "
                            "context menu or from the volume snapshot refinem"
                            "ent dialog window.", 2);
        return -1; // Do not call any other X-Tension function

    case XT_ACTION_LSS:
    case XT_ACTION_PSS:
    case XT_ACTION_SHC:
        XWF_OutputMessage (L"WARNING: Griffeye XML export X-Tension is not su"
                            "pposed to run during searches. The X-Tension wil"
                            "l not be executed.", 2);
        return -3; // Prevent further X-Tension use for this operation type

    case XT_ACTION_RVS:
        // Volume snapshot refinement ahead, ask to call XT_ProcessItemEx
        // on every file, after all other refinement operations are done.
        return_value = XT_PREPARE_CALLPI | XT_PREPARE_CALLPILATE;
        break;

    case XT_ACTION_DBC:
        // Executed from directory browser context menu, no need to return
        // anything special.
        return_value = 0;
        break;

    default:
        XWF_OutputMessage (L"ERROR: Griffeye XML export X-Tension does not su"
                            "pport this mode of operation. Aborting.", 2);
        return -1; // Do not call any other X-Tension function
    }

    // Silent fail condition
    if (L'\0' == export_dir[0])
    {
        return -1;
    }

    WCHAR longname[NAME_BUF_LEN];
    WCHAR shortname[NAME_BUF_LEN];
    WCHAR name_ex[NAME_BUF_LEN];

    // Long (type 1) name examples:
    //   [X:\Full\Path\ImageName.ext]
    //   [X:\Full\Path\ImageName.ext], Partition 1
    XWF_GetVolumeName (hVolume, longname, 1);
    // Short (type 2) name examples:
    //   ImageName
    //   ImageName, Partition 1
    XWF_GetVolumeName (hVolume, shortname, 2);

    // Store volume name before truncating
    StringCchCopyW (name_ex, NAME_BUF_LEN, shortname);

    // We will group exported files by evidence item, not by partition.
    // If the shortname contains a suffix, the substring lookup will fail.
    if (NULL == wcsstr (longname, shortname))
    {
        // Find the last occurence of ", " and cut the string there
        size_t pos = wcslen (shortname);
        while (1 < pos)
        {
            if (L' ' == shortname[pos--]
                && L',' == shortname[pos])
            {
                shortname[pos] = L'\0';
                break;
            }
        }
    }

    // Remove any illegal filename characters beforehand
    for (int i = 0; i < wcslen (shortname); i++)
    {
        switch (shortname[i])
        {
        case L'\\':
        case L'/':
        case L':':
        case L'*':
        case L'?':
        case L'\"':
        case L'<':
        case L'>':
        case L'|':
            shortname[i] = L'_';
        }
    }

    BOOL volume_exists = SetCurrentVolume (shortname);

    // Update extended name for <fullpath> report tag
    StringCchCopyW (current_volume->name_ex, NAME_BUF_LEN, name_ex);

    if (volume_exists)
    {
        return return_value;
    }

    // New volume was created, initialize current_volume
    StringCchCopyW (current_volume->name, NAME_BUF_LEN, shortname);

    // We need to create new report files only if we are to split evidence
    // items in separate directories. Otherwise, all reports and folders were
    // already created in XT_Init.
    if (split_evidence_items)
    {
        PWSTR volume_dir = NULL;
        PathAllocCombine (export_dir, current_volume->name, 0, &volume_dir);
        BOOL success = XmlCreateReportFiles (volume_dir);
        LocalFree (volume_dir);

        if (success)
        {
            return return_value;
        }
        else
        {
            XWF_OutputMessage (L"ERROR: Griffeye XML export X-Tension could n"
                                "ot create a file. Aborting.", 2);
            // Returning -1 would prevent the XT_Finalize call, use
            // silent fail condition in XT_ProcessItemEx instead.
            export_dir[0] = L'\0';
            return 0;
        }
    }
    else
    {
        // Reference global XtReport structure
        current_volume->report = first_volume->report;
        current_volume->report->ref_count++;

        return return_value;
    }
}

// Called for every file
EXPORT LONG XTAPI
XT_ProcessItemEx (LONG nItemID, HANDLE hItem, PVOID lpReserved)
{
    // Silent fail condition
    if (L'\0' == export_dir[0])
    {
        return 0;
    }
    // This should never happen
    if (NULL == current_volume)
    {
        XWF_OutputMessage (L"ERROR: Griffeye XML export X-Tension could not a"
                            "ssociate the file with a volume. Aborting.", 2);
        return -1;
    }

    // Check if we have a file from 'Pictures' or 'Video' category
    WCHAR type_buf[32];
    DWORD len   = 32;
    DWORD flags = 0x40000000; // File type category
    int   type  = TYPE_OTHER;

    if (-1 == XWF_GetItemType (nItemID, type_buf, len | flags))
    {
        return 0;
    }
    if (0 == lstrcmpW (type_buf, L"Pictures"))
    {
        type = TYPE_PICTURE;
        current_volume->report->image_count++;
    }
    else if (0 == lstrcmpW (type_buf, L"Video"))
    {
        type = TYPE_VIDEO;
        current_volume->report->movie_count++;
    }
    else
    {
        // Not a picture or video file, ignore
        return 0;
    }

    WCHAR filepath[MAX_PATH] = { 0 };
    WCHAR filename[MAX_PATH] = { 0 };

    // Grab all necessary metadata
    struct XtFile fi = { 0 };

    fi.created  = GET_ITEM_TIME (XWF_ITEM_INFO_CREATIONTIME);
    fi.accessed = GET_ITEM_TIME (XWF_ITEM_INFO_LASTACCESSTIME);
    fi.written  = GET_ITEM_TIME (XWF_ITEM_INFO_MODIFICATIONTIME);
    fi.filesize = XWF_GetItemSize (nItemID);

    if (-1 == fi.filesize)
    {
        // Should never happen for valid files, ignore
        return 0;
    }

    // Recursively concatenate full file path
    StringCchCopyW (filepath, MAX_PATH, XWF_GetItemName (nItemID));
    LONG parent      = XWF_GetItemParent (nItemID);
    LONG grandparent = parent;

    // Last valid parent item always is called "(Root directory)"
    // We need to check parent and grandparent to discard this
    if (-1 != parent)
    {
        grandparent = XWF_GetItemParent (parent);
    }
    while (-1 != grandparent)
    {
        StringCchCopyW (filename, MAX_PATH, XWF_GetItemName (parent));
        PathCchAppend  (filename, MAX_PATH, filepath);
        StringCchCopyW (filepath, MAX_PATH, filename);

        parent = XWF_GetItemParent (parent);
        if (-1 == parent)
        {
            break;
        }
        grandparent = XWF_GetItemParent (parent);
    }
    PathCchCombine (fi.fullpath, MAX_PATH, current_volume->name_ex, filepath);

    // filepath = root export directory for this evidence item
    StringCchCopyW (filepath, MAX_PATH, current_volume->report->export_path);
    // filepath = filepath + [Pictures|Movies]
    switch (type)
    {
    case TYPE_PICTURE:
        PathCchAppend (filepath, MAX_PATH, IMG_SUBDIR);
        fi.id = current_volume->report->image_count;
        XmlAppendImage (&fi);
        break;
    case TYPE_VIDEO:
        PathCchAppend (filepath, MAX_PATH, VID_SUBDIR);
        fi.id = current_volume->report->movie_count;
        XmlAppendMovie (&fi);
        break;
    }
    // filepath = filepath + file number
    StringCchPrintfW (filename, MAX_PATH, L"%lld", fi.id);
    PathCchAppend (filepath, MAX_PATH, filename);

    if (!ExportXwfFile (hItem, filepath, fi.filesize))
    {
        XWF_OutputMessage (L"ERROR: Griffeye XML export X-Tension could not w"
                            "rite to export directory. Aborting.", 2);
        XWF_OutputMessage (L"Error on file:", 2);
        XWF_OutputMessage (filepath, 3);
    }
    else
    {
        XWF_AddToRepTable (nItemID, REP_TABLE, 1);
    }

    return 0;
}

// Called once after processing all volumes
EXPORT LONG XTAPI
XT_Done (PVOID lpReserved)
{
    struct XtVolume * tmp = NULL;
    struct XtVolume * vol = first_volume;

    while (vol)
    {
        vol->report->ref_count--;
        if (0 == vol->report->ref_count)
        {
            // This is the last reference, close tags and release files
            XmlWriteString (vol->report->xml_image_index, L"</ReportIndex>");
            XmlWriteString (vol->report->xml_movie_index, L"</ReportIndex>");

            CloseHandle (vol->report->xml_case_report);
            CloseHandle (vol->report->xml_image_index);
            CloseHandle (vol->report->xml_movie_index);

            // One log entry per evidence item
            WCHAR buf[512];
            StringCchPrintfW (buf, 512,
                              L"Exported %d images and %d videos to %s",
                              vol->report->image_count,
                              vol->report->movie_count,
                              vol->report->export_path);
            XWF_OutputMessage (buf, 2);

            // Remove any empty export directories
            LPWSTR dir = vol->report->export_path;

            PWSTR img_subdir  = NULL;
            PWSTR vid_subdir  = NULL;
            PWSTR case_report = NULL;
            PWSTR image_index = NULL;
            PWSTR movie_index = NULL;

            PathAllocCombine (dir, IMG_SUBDIR,  0, &img_subdir);
            PathAllocCombine (dir, VID_SUBDIR,  0, &vid_subdir);
            PathAllocCombine (dir, CASE_REPORT, 0, &case_report);
            PathAllocCombine (dir, IMG_REPORT,  0, &image_index);
            PathAllocCombine (dir, VID_REPORT,  0, &movie_index);

            if (0 == vol->report->image_count)
            {
                DeleteFileW (image_index);
                RemoveDirectoryW (img_subdir);
            }
            if (0 == vol->report->movie_count)
            {
                DeleteFileW (movie_index);
                RemoveDirectoryW (vid_subdir);
            }
            if (0 == vol->report->image_count
                && 0 == vol->report->movie_count)
            {
                DeleteFileW (case_report);
                RemoveDirectoryW (dir);
            }

            LocalFree (img_subdir);
            LocalFree (vid_subdir);
            LocalFree (case_report);
            LocalFree (image_index);
            LocalFree (movie_index);

            free (vol->report);
        }

        tmp = vol;
        vol = vol->next;
        free (tmp);
    }

    return 0;
}

EXPORT LONG XTAPI
XT_About (HANDLE hParentWnd, PVOID lpReserved)
{
    LPCWSTR about = L"Griffeye XML export X-Tension\n\nThis X-Tension allows "
                     "you to create C4All reports which can be imported by Gr"
                     "iffeye Analyze. You can choose to merge all evidence it"
                     "ems into a single report or to separate them into subdi"
                     "rectories. Either way the XML reports will contain the "
                     "full file path starting with the evidence item name and"
                     " partition number.\n\nSource code available at:\nhttps:"
                     "//github.com/Naufragous/xt-gexpo\n\nAuthor: R. Yushaev";
    MessageBoxW (NULL, about, L"About", MB_ICONINFORMATION);

    return 0;
}

BOOL WINAPI
DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
