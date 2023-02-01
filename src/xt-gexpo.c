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
#define IMG_SUBDIR  L"Pictures"
#define VID_SUBDIR  L"Movies"
#define CASE_REPORT L"Case Report.xml"
#define IMG_REPORT  L"C4P Index.xml"
#define VID_REPORT  L"C4M Index.xml"
#define MIN_VER     1760
#define MIN_VER_S   L"17.6"

#define REP_TABLE_SUCCESS L"[XT][gexpo] exported"
#define REP_TABLE_FAILED  L"[XT][gexpo] could not read file"

#define NAME_BUF_LEN 256
#define BIG_BUF_LEN  2048

#define TYPE_OTHER   0
#define TYPE_PICTURE 1
#define TYPE_VIDEO   2

//1 * 1024 * 1024 * 1024 = 1.073.741.824 = 1GB --> size of data that is used to read and write large files
#define FILE_CHUNK 1073741824
//2 * 1024 * 1024 * 1024 = 2.147.483.648 = 2GB, this variable is used to determine what is considered a "large" file
#define FILE_2GB 2147483648

#define EXPORT __declspec (dllexport)

struct XtFile
{
    INT64 export_id;
    INT64 created;
    INT64 accessed;
    INT64 written;
    INT64 filesize;

    WCHAR fullpath[BIG_BUF_LEN];
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
    UINT32 empty_count;
    UINT32 size_mismatch_count;
    UINT32 inaccessible_count;

    HANDLE xml_case_report;
    HANDLE xml_image_index;
    HANDLE xml_movie_index;

    WCHAR export_path[MAX_PATH];
};

// Small struct for file enumeration
struct XtFileId
{
    INT64 xwf_id;
    int type;
};

struct XtVolume
{
    struct XtVolume * next;
    struct XtReport * report;

    struct XtFileId * file_ids;
    struct XtFile   * files;

    // Amount of enumerated file IDs
    INT64 file_count;

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

HANDLE hXwfWnd = NULL;

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

typedef LONG   (XTAPI * fp_XWF_AddToReportTable) (LONG, LPWSTR, DWORD);
typedef VOID   (XTAPI * fp_XWF_Close) (HANDLE);
typedef INT64  (XTAPI * fp_XWF_GetCaseProp) (LPVOID, LONG, PVOID, LONG);
typedef HANDLE (XTAPI * fp_XWF_GetFirstEvObj) (LPVOID);
typedef DWORD  (XTAPI * fp_XWF_GetItemCount) (LPVOID);
typedef INT64  (XTAPI * fp_XWF_GetItemInformation) (LONG, LONG, LPBOOL);
typedef LPWSTR (XTAPI * fp_XWF_GetItemName) (LONG);
typedef LONG   (XTAPI * fp_XWF_GetItemParent) (LONG);
typedef INT64  (XTAPI * fp_XWF_GetItemSize) (LONG);
typedef LONG   (XTAPI * fp_XWF_GetItemType) (LONG, LPWSTR, DWORD);
typedef HANDLE (XTAPI * fp_XWF_GetNextEvObj) (HANDLE, LPVOID);
typedef VOID   (XTAPI * fp_XWF_GetVolumeName) (HANDLE, LPWSTR, DWORD);
typedef VOID   (XTAPI * fp_XWF_HideProgress) ();
typedef HANDLE (XTAPI * fp_XWF_OpenItem) (HANDLE, LONG, DWORD);
typedef void   (XTAPI * fp_XWF_OutputMessage) (LPWSTR, DWORD);
typedef DWORD  (XTAPI * fp_XWF_Read) (HANDLE, INT64, LPVOID, DWORD);
typedef VOID   (XTAPI * fp_XWF_SetProgressDescription) (LPWSTR);
typedef VOID   (XTAPI * fp_XWF_SetProgressPercentage) (DWORD);
typedef BOOL   (XTAPI * fp_XWF_ShouldStop) ();
typedef VOID   (XTAPI * fp_XWF_ShowProgress) (LPWSTR, DWORD);

fp_XWF_AddToReportTable       XWF_AddToReportTable       = NULL;
fp_XWF_Close                  XWF_Close                  = NULL;
fp_XWF_GetCaseProp            XWF_GetCaseProp            = NULL;
fp_XWF_GetFirstEvObj          XWF_GetFirstEvObj          = NULL;
fp_XWF_GetItemCount           XWF_GetItemCount           = NULL;
fp_XWF_GetItemInformation     XWF_GetItemInformation     = NULL;
fp_XWF_GetItemName            XWF_GetItemName            = NULL;
fp_XWF_GetItemParent          XWF_GetItemParent          = NULL;
fp_XWF_GetItemSize            XWF_GetItemSize            = NULL;
fp_XWF_GetItemType            XWF_GetItemType            = NULL;
fp_XWF_GetNextEvObj           XWF_GetNextEvObj           = NULL;
fp_XWF_GetVolumeName          XWF_GetVolumeName          = NULL;
fp_XWF_HideProgress           XWF_HideProgress           = NULL;
fp_XWF_OpenItem               XWF_OpenItem               = NULL;
fp_XWF_OutputMessage          XWF_OutputMessage          = NULL;
fp_XWF_Read                   XWF_Read                   = NULL;
fp_XWF_SetProgressDescription XWF_SetProgressDescription = NULL;
fp_XWF_SetProgressPercentage  XWF_SetProgressPercentage  = NULL;
fp_XWF_ShouldStop             XWF_ShouldStop             = NULL;
fp_XWF_ShowProgress           XWF_ShowProgress           = NULL;

VOID
GetXwfFunctions ()
{
    HMODULE h = GetModuleHandleW (NULL);

    #define LOAD_FUNCTION(x) (x = (fp_ ## x) GetProcAddress (h, #x))

    LOAD_FUNCTION (XWF_AddToReportTable);
    LOAD_FUNCTION (XWF_Close);
    LOAD_FUNCTION (XWF_GetCaseProp);
    LOAD_FUNCTION (XWF_GetFirstEvObj);
    LOAD_FUNCTION (XWF_GetItemCount);
    LOAD_FUNCTION (XWF_GetItemInformation);
    LOAD_FUNCTION (XWF_GetItemName);
    LOAD_FUNCTION (XWF_GetItemParent);
    LOAD_FUNCTION (XWF_GetItemSize);
    LOAD_FUNCTION (XWF_GetItemType);
    LOAD_FUNCTION (XWF_GetNextEvObj);
    LOAD_FUNCTION (XWF_GetVolumeName);
    LOAD_FUNCTION (XWF_HideProgress);
    LOAD_FUNCTION (XWF_OpenItem);
    LOAD_FUNCTION (XWF_OutputMessage);
    LOAD_FUNCTION (XWF_Read);
    LOAD_FUNCTION (XWF_SetProgressDescription);
    LOAD_FUNCTION (XWF_SetProgressPercentage);
    LOAD_FUNCTION (XWF_ShouldStop);
    LOAD_FUNCTION (XWF_ShowProgress);
}

// Returns 1 if all function pointers have been initialized
// Returns 0 if at least one function pointer is NULL
DWORD
CheckXwfFunctions ()
{
    return (XWF_AddToReportTable
         && XWF_Close
         && XWF_GetCaseProp
         && XWF_GetFirstEvObj
         && XWF_GetItemCount
         && XWF_GetItemInformation
         && XWF_GetItemName
         && XWF_GetItemParent
         && XWF_GetItemSize
         && XWF_GetItemType
         && XWF_GetNextEvObj
         && XWF_GetVolumeName
         && XWF_HideProgress
         && XWF_OpenItem
         && XWF_OutputMessage
         && XWF_Read
         && XWF_SetProgressDescription
         && XWF_SetProgressPercentage
         && XWF_ShouldStop
         && XWF_ShowProgress
         ) ? 1 : 0;
}

// Expands provided path on dialog initialization
BFFCALLBACK
MyCallback (HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData)
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

    bi.hwndOwner = hXwfWnd;
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
            MessageBoxW (hXwfWnd,
                         L"The selected directory already contains a Griffeye"
                          " export folder. Plese select another directory.",
                         L"Notice",
                         MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxW (hXwfWnd,
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

// A simpler implementation of PathCchAppendEx without extensive checks.
// The WinAPI is too smart for our use case and can cut off path parts,
// e.g. when the file name of an embedded file extracted by X-Ways contains
// an absolute path including a drive letter.
VOID
MyPathAppend (PWSTR pszPath, size_t cchPath, PCWSTR pszMore)
{
    if (NULL == pszPath || NULL == pszMore)
    {
        return;
    }

    size_t l_path = wcslen (pszPath);
    // Check if we have enough space for backslash and null terminator
    if (cchPath - 1 < l_path + 1)
    {
        return;
    }
    // Append backslash if necessary
    if (L'\\' != pszPath[l_path - 1] && L'\\' != pszMore[0])
    {
        pszPath[l_path++] = L'\\';
    }
    size_t i = 0;
    while (cchPath - 1 > l_path)
    {
        if (L'\0' == pszMore[i])
        {
            break;
        }
        pszPath[l_path++] = pszMore[i++];
    }
    pszPath[l_path] = L'\0';
}

BOOL
IsCharOutOfXmlRange (WCHAR c)
{
    // Char ::= #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    switch (c)
    {
    case 0x09:
    case 0x0a:
    case 0x0d:
        return 0;
    }
    if (0x000020 > c)                 return 1;
    if (0x00d7ff < c && 0x00e000 > c) return 1;
    if (0x00fffd < c && 0x010000 > c) return 1;
    if (0x10ffff < c)                 return 1;
    return 0;
}

// Replaces unsupported characters according to XML recommendation 1.0, §2.2
VOID
XmlSanitizeString (PWSTR str)
{
    if (NULL == str)
    {
        return;
    }

    size_t l = wcslen (str);
    for (size_t i = 0; i < l; i++)
    {
        if (IsCharOutOfXmlRange (str[i]))
        {
            str[i] = L'_';
        }
    }
}

BOOL
GetXwfFileInfo (LONG nItemID, struct XtFile * file)
{
    // Converts WinAPI FILETIME to unix epoch time
    #define GET_ITEM_TIME(x) (XWF_GetItemInformation (nItemID, (x), NULL) \
                              / 10000000 - 11644473600LL)

    file->created  = GET_ITEM_TIME (XWF_ITEM_INFO_CREATIONTIME);
    file->accessed = GET_ITEM_TIME (XWF_ITEM_INFO_LASTACCESSTIME);
    file->written  = GET_ITEM_TIME (XWF_ITEM_INFO_MODIFICATIONTIME);
    if (0 > file->created)  file->created  = 0;
    if (0 > file->accessed) file->accessed = 0;
    if (0 > file->written)  file->written  = 0;

    file->filesize = XWF_GetItemSize (nItemID);
    if (1 > file->filesize)
    {
        // Should never happen for valid files, ignore
        current_volume->report->empty_count++;
        return 0;
    }

    WCHAR filepath[BIG_BUF_LEN] = { 0 };
    WCHAR filename[BIG_BUF_LEN] = { 0 };

    // Recursively concatenate full file path
    StringCchCopyW (filepath, BIG_BUF_LEN, XWF_GetItemName (nItemID));
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
        StringCchCopyW (filename, BIG_BUF_LEN, XWF_GetItemName (parent));
        MyPathAppend   (filename, BIG_BUF_LEN, filepath);
        StringCchCopyW (filepath, BIG_BUF_LEN, filename);

        parent = XWF_GetItemParent (parent);
        if (-1 == parent)
        {
            break;
        }
        grandparent = XWF_GetItemParent (parent);
    }
    StringCchCopyW (file->fullpath, BIG_BUF_LEN, current_volume->name_ex);
    MyPathAppend   (file->fullpath, BIG_BUF_LEN, filepath);
    
    XmlSanitizeString (file->fullpath);

    return 1;
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
         && XmlWriteString (file, L"<CaseReport>\r\n  <CaseNumber><![CDATA[")
         && XmlWriteString (file, case_name)
         && XmlWriteString (file, L"]]></CaseNumber>\r\n  <Date><![CDATA[")
         && XmlWriteString (file, date)
         && XmlWriteString (file, L"]]></Date>\r\n  <Time><![CDATA[")
         && XmlWriteString (file, time)
         && XmlWriteString (file, L"]]></Time>\r\n  <Comment><![CDATA[Created"
                                   " by Griffeye XML export X-Tension: https:"
                                   "//github.com/Naufragous/xt-gexpo/ ]]></Co"
                                   "mment>\r\n  <DLLversion><![CDATA[V1.0]]><"
                                   "/DLLversion>\r\n  <XwaysVersion><![CDATA[")
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

    StringCchPrintfW (id,    32, L"%lld", xf->export_id);
    StringCchPrintfW (ctime, 32, L"%lld", xf->created);
    StringCchPrintfW (atime, 32, L"%lld", xf->accessed);
    StringCchPrintfW (wtime, 32, L"%lld", xf->written);
    StringCchPrintfW (size,  32, L"%lld", xf->filesize);

    return (XmlWriteString (file, L"<")
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
         && XmlWriteString (file, L"</id>\r\n  <category>0</category>\r\n  <f"
                                   "ileoffset>0</fileoffset>\r\n  <fullpath><"
                                   "![CDATA[")
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
                            "y. Aborting.", 0);
        return 1;
    }

    hXwfWnd = hMainWnd;

    // Get case name for our Case Report.xml
    // Also check if we have any case at all
    if (-1 == XWF_GetCaseProp (NULL, XWF_CASEPROP_TITLE,
                               case_name, NAME_BUF_LEN))
    {
        XWF_OutputMessage (L"NOTICE: Griffeye XML export X-Tension needs an a"
                            "ctive case. Aborting.", 0);
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
                            "lid export directory. Aborting.", 0);
        return 1;
    }

    XWF_OutputMessage (L"Griffeye XML export target:", 0);
    XWF_OutputMessage (export_dir, 1);

    HANDLE first_obj = XWF_GetFirstEvObj (NULL);
    if (!first_obj)
    {
        // Empty case
        XWF_OutputMessage (L"ERROR: Griffeye XML export X-Tension needs an ev"
                            "idence item to work on. Aborting.", 0);
        export_dir[0] = L'\0';
        return 1;
    }
    int create_global_report = 0;
    // If there is more than one evidence item, ask the user whether we should
    // split exported files and create a subdirectory for every evidence item.
    if (XWF_GetNextEvObj (first_obj, NULL))
    {
        LPCWSTR cap = L"Do you want a merged export?";
        LPCWSTR msg = L"This case contains several evidence items. Griffeye X"
                       "ML export X-Tension can either create separate export"
                       "s for each evidence item or one export with files fro"
                       "m all evidence items. In any case, the file path will"
                       " include the name of the evidence item and volume.\n "
                       "\nDo you want to merge all exports into one?";
        if (IDNO == MessageBoxW (hXwfWnd, msg, cap, MB_YESNO | MB_ICONINFORMATION))
        {
            split_evidence_items = 1;
        }
        else
        {
            create_global_report = 1;
        }
    }
    else
    {
        // There is only one evidence item
        create_global_report = 1;
    }
    if (create_global_report)
    {
        // Our first volume will be a dummy one and will just serve as a
        // link to the global XtReport structure.
        current_volume = calloc (1, sizeof (struct XtVolume));
        first_volume   = current_volume;
        if (0 == XmlCreateReportFiles (export_dir))
        {
            XWF_OutputMessage (L"ERROR: Griffeye XML export X-Tension could n"
                                "ot create a file. Aborting.", 0);
            export_dir[0] = L'\0';
            return 1;
        }
    }

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
                            "ent dialog window.", 0);
        return -1; // Do not call any other X-Tension function

    case XT_ACTION_LSS:
    case XT_ACTION_PSS:
    case XT_ACTION_SHC:
        XWF_OutputMessage (L"WARNING: Griffeye XML export X-Tension is not su"
                            "pposed to run during searches. The X-Tension wil"
                            "l not be executed.", 0);
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
                            "pport this mode of operation. Aborting.", 0);
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
    XWF_GetVolumeName (hVolume, shortname, 0);

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

    // Find or create volume struct
    BOOL volume_exists = SetCurrentVolume (shortname);

    // Allocate enough memory for all files
    DWORD item_count = XWF_GetItemCount (NULL);
    if (current_volume->file_ids)
    {
        free (current_volume->file_ids);
    }
    current_volume->file_ids = malloc (sizeof (struct XtFileId) * item_count);
    current_volume->file_count = 0;

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
                                "ot create a file. Aborting.", 0);
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
XT_ProcessItem (LONG nItemID, PVOID lpReserved)
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
                            "ssociate the file with a volume. Aborting.", 0);
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
    }
    else if (0 == lstrcmpW (type_buf, L"Video"))
    {
        type = TYPE_VIDEO;
    }
    else
    {
        // Not a picture or video file, ignore
        return 0;
    }

    // Enumerate file for further processing
    INT64 fc = current_volume->file_count++;
    current_volume->file_ids[fc].xwf_id = nItemID;
    current_volume->file_ids[fc].type   = type;

    return 0;
}

// Called after processing every volume
EXPORT LONG XTAPI
XT_Finalize (HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, PVOID lpReserved)
{
    const INT64 fc = current_volume->file_count;
    if(0 == fc || NULL == current_volume->file_ids)
    {
        return 0;
    }
    // Allocate enough memory for relevant files
    if (current_volume->files)
    {
        free (current_volume->files);
    }
    current_volume->files = malloc (sizeof (struct XtFile) * fc);

    struct XtReport * report   = current_volume->report;
    struct XtFileId * file_ids = current_volume->file_ids;
    struct XtFile   * files    = current_volume->files;

    // We will calculate actual export progress by size, not by file count
    INT64 total_size    = 0;
    INT64 exported_size = 0;

    // Grab all necessary metadata
    XWF_ShowProgress (L"[XT] Collecting metadata", 4);
    XWF_SetProgressPercentage (0);
    for (INT64 i = 0; i < fc; i++)
    {
        if (XWF_ShouldStop ())
        {
            return 0;
        }
        if (GetXwfFileInfo (file_ids[i].xwf_id, &files[i]))
        {
            total_size += files[i].filesize;
        }
        else
        {
            files[i].export_id = -1;
        }
        XWF_SetProgressPercentage ((i + 1) * 100 / fc);
    }
    XWF_HideProgress ();

    // Export files
    XWF_ShowProgress (L"[XT] Exporting files", 4);
    XWF_SetProgressPercentage (0);
    WCHAR filepath[MAX_PATH] = { 0 };
    WCHAR filename[MAX_PATH] = { 0 };
    for (INT64 i = 0; i < fc; i++)
    {
        if (XWF_ShouldStop ())
        {
            return 1;
        }
        if (-1 == files[i].export_id)
        {
            continue;
        }
        // filepath = root export directory for this evidence item
        StringCchCopyW (filepath, MAX_PATH, report->export_path);
        // filepath = filepath + [Pictures|Movies]
        switch (file_ids[i].type)
        {
        case TYPE_PICTURE:
            PathCchAppend (filepath, MAX_PATH, IMG_SUBDIR);
            files[i].export_id = report->image_count + 1;
            break;
        case TYPE_VIDEO:
            PathCchAppend (filepath, MAX_PATH, VID_SUBDIR);
            files[i].export_id = report->movie_count + 1;
            break;
        }
        // filepath = filepath + file number
        StringCchPrintfW (filename, MAX_PATH, L"%lld", files[i].export_id);
        PathCchAppend (filepath, MAX_PATH, filename);

        int export_successful = 0;
        // It is possible that we will get less bytes from XWF_Read
        INT64 expected_size = files[i].filesize;
        // Since we are accessing file data outside of ProcessItemEx,
        // we need to manually open and close the file handle.
        HANDLE hItem = XWF_OpenItem (hVolume, file_ids[i].xwf_id, 1);
        if (0 == hItem)
        {
            // This happens when X-Ways cannot access the file contents
            XWF_AddToReportTable (file_ids[i].xwf_id, REP_TABLE_FAILED, 1);
            current_volume->report->inaccessible_count++;
        }
        else
        {
            // declare all variables we need for reading the current file...
            INT64 i64DataSizeRead = 0;       //amount of data of the current file that has already been processed
            INT64 i64DataSizeToRead = 0;     //determines how much data to read in this iteration
            HANDLE file = NULL;
            DWORD actual_size = 0;

            // Start of loop for exporting files...
            while ((i64DataSizeRead < expected_size))
            {
                //if expected size - already read data >= chunk of data we want to read  --> we can still read a full chunk of data
                //else read however much is left of the file
                if (expected_size - i64DataSizeRead >= FILE_CHUNK)
                {
                    i64DataSizeToRead = FILE_CHUNK;
                }
                else
                {
                    i64DataSizeToRead = expected_size - i64DataSizeRead;
                }

                //allocate memory
                LPVOID filebuf = malloc(i64DataSizeToRead);

                if (NULL == filebuf)
                {
                    XWF_Close(hItem);
                    XWF_OutputMessage(L"ERROR: Griffeye XML export X-Tension cou"
                                      "ld not allocate memory for file export. "
                                      "Aborting.", 0);

                    // print erroring file
                    // implicit conversion of wchar array to wstring pointer
                    LPWSTR FileErrorPath = files[i].fullpath;
                    XWF_OutputMessage(FileErrorPath, 0);

                    XWF_HideProgress();
                    return 1;
                }

                // Actual size can be less (or even zero)
                actual_size = XWF_Read(hItem, i64DataSizeRead, filebuf, i64DataSizeToRead);
                //remove the following "if" as soon as XWF_Read return value is fixed
                //only overwrite actual_size if file is considered to be large because XWF_Read is returning 0 in that case --> should be fixed in future releases of X-Ways according to S. Fleischmann
                if ((actual_size == 0) && (expected_size >= FILE_2GB))
                {
                    actual_size = i64DataSizeToRead;
                }

                //remember the amount of data we just read, to be able to calculate how much to read in the next iteration
                i64DataSizeRead = i64DataSizeRead + i64DataSizeToRead;

                if (0 == actual_size)
                {
                    // Happens when X-Ways reports a filesize > 0 but the file
                    // reference does not contain any actual data.
                    free(filebuf);
                    current_volume->report->empty_count++;
                }
                else
                {
                    // Create file on first iteration, but only when we are actually going to export data
                    if (NULL == file) {
                        file = MyCreateFile(filepath);
                    }
                    if (INVALID_HANDLE_VALUE == file)
                    {
                        XWF_Close(hItem);
                        free(filebuf);
                        XWF_OutputMessage(L"ERROR: Griffeye XML export X-Tension cou"
                                          "ld not create a file in the export direc"
                                          "tory. Aborting.", 0);

                        XWF_HideProgress();
                        return 1;
                    }

                    BOOL rv = WriteFile(file, filebuf, actual_size, NULL, NULL);
                    free(filebuf);

                    if (FALSE == rv)
                    {
                        CloseHandle(file);
                        XWF_Close(hItem);
                        XWF_OutputMessage(L"ERROR: Griffeye XML export X-Ten"
                                          "sion could not write to export d"
                                          "irectory. Aborting.", 0);
                        XWF_HideProgress();
                        return 1;
                    }
                    // If we came this far, at least some data has been exported
                    export_successful = 1;
                }//XWF_Read return > 0
            } //while loop exporting file

            CloseHandle(file);
            XWF_Close(hItem);

            XWF_AddToReportTable(file_ids[i].xwf_id, REP_TABLE_SUCCESS, 1);

        }//XWF could access current file

        // Only add XML entry if at least some data was exported
        if (export_successful)
        {
            switch (file_ids[i].type)
            {
                case TYPE_PICTURE:
                    report->image_count++;
                    XmlAppendImage (&files[i]);
                    break;
                case TYPE_VIDEO:
                    report->movie_count++;
                    XmlAppendMovie (&files[i]);
                    break;
            }
        }
        // Advance progress by expected file size regardless of result
        exported_size += expected_size;
        XWF_SetProgressPercentage (exported_size * 100 / total_size);
    }
    XWF_HideProgress ();

    free (current_volume->file_ids);
    free (current_volume->files);
    current_volume->file_ids = NULL;
    current_volume->files    = NULL;

    // Return 1 to refresh current directory listing.
    // This is necessary if you want to immediately display
    // new report table associations.
    return 1;
}

// Called once after processing all volumes
EXPORT LONG XTAPI
XT_Done (PVOID lpReserved)
{
    struct XtVolume * tmp = NULL;
    struct XtVolume * vol = first_volume;

    while (vol)
    {
        if (vol->report && 1 == vol->report->ref_count--)
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
                              L"Exported %d images and %d videos",
                              vol->report->image_count,
                              vol->report->movie_count);
            XWF_OutputMessage (buf, 0);
            if (vol->report->size_mismatch_count)
            {
                StringCchPrintfW (buf, 512,
                                  L"[*] including %d files with inaccurate si"
                                   "ze (see report table)",
                                  vol->report->size_mismatch_count);
                XWF_OutputMessage (buf, 0);
            }
            if (vol->report->inaccessible_count)
            {
                StringCchPrintfW (buf, 512,
                                  L"[*] excluding %d inaccessible files (see "
                                    "report table)",
                                  vol->report->inaccessible_count);
                XWF_OutputMessage (buf, 0);
            }
            if (vol->report->empty_count)
            {
                StringCchPrintfW (buf, 512,
                                  L"[*] excluding %d empty files",
                                  vol->report->empty_count);
                XWF_OutputMessage (buf, 0);
            }

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
            vol->report = NULL;
        }

        free (vol->file_ids);
        free (vol->files);
        vol->file_ids = NULL;
        vol->files    = NULL;

        tmp = vol;
        vol = vol->next;

        free (tmp);
        tmp = NULL;
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
    MessageBoxW (hXwfWnd, about, L"About", MB_ICONINFORMATION);

    return 0;
}

BOOL WINAPI
DllMain (HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    return TRUE;
}
