# Griffeye XML export X-Tension

This X-Tension allows you to export images and videos from X-Ways Forensics in
the C4All format. You can then import the XML indexes in Griffeye Analyze.

## Requirements
* Windows 10
* X-Ways Forensics 17.6 or later

## Installation
* Download the [32-bit or 64-bit Release](https://github.com/ThePixelbrain/xt-gexpo/releases).
* Execute the X-Tension either by checking the *Run X-Tensions* box in the
*Refine Volume Snapshot* window or by selecting *Run X-Tensions* from the
directory browser context menu.

## Building from source
* Open the Visual Studio Command Prompt
(e.g. *VS 2015 x86 Native Tools* or *VS 2015 x64 Native Tools*).
* Run **nmake win32** or **nmake win64** in the project directory.

## Using the auto export feature
The auto export feature allows you to automatically specify an export directory without any user input.
This effectively makes the extension fully automatable without any user input required.

The following steps are required to use the feature:
* Create a file in the parent directory of the current case named `xt-gexpo.conf`.
* Put the export directory path in the file. (e.g. `D:\Export`) 
* When starting the extension, a subdirectory with the case name will be created inside that directory automatically.
  The file dialog to select the export directory will be skipped.

An export structure might look like this:
```
D:\Export\CaseName
└───Griffeye Export
    ├───Deleted
    │   └───Evidence Item
    │       ├───Movies
    │       └───Pictures
    └───Existing
        └───Evidence Item
            ├───Movies
            └───Pictures
```

## License
GNU Affero General Public License v3.0.

## Links
* [X-Ways Forensics](http://www.x-ways.net/forensics/)
