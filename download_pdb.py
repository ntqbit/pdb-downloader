from typing import Optional

import os
import argparse
import asyncio
import aiohttp
import pefile

class ExtractPdbException(Exception):
    pass


class NoDebugEntryException(ExtractPdbException):
    pass


class UnsupportedDebugEntryTypeError(ExtractPdbException):
    pass


class DownloadPdbException(Exception):
    pass


class UnexpectedReturnStatusError(DownloadPdbException):
    pass


class PdbNotFoundError(DownloadPdbException):
    pass


class PdbInfo:
    def __init__(self, pdb_signature: str, pdbfilename: str):
        self.pdb_signature = pdb_signature
        self.pdbfilename = pdbfilename
    
    def __repr__(self) -> str:
        return f'PdbInfo(signature={self.pdb_signature},filename={self.pdbfilename})'

    def basename(self) -> str:
        # Do not use os.path.basename since it is platform dependent,
        # and will not take the basename from a windows path on linux
        # Support / directory separator, even though it is rarely used on windows.
        last_slash = self.pdbfilename.rfind('/')
        last_slash = max(last_slash, self.pdbfilename.rfind('\\'))

        if last_slash == -1:
            return self.pdbfilename
        else:
            return self.pdbfilename[last_slash+1:]


async def extract_pdb_info(pe_data: bytes) -> PdbInfo:
    pe = pefile.PE(data=pe_data)
    
    if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') or len(pe.DIRECTORY_ENTRY_DEBUG) == 0:
        raise NoDebugEntryException()

    debug_entry = pe.DIRECTORY_ENTRY_DEBUG[0].entry
    if debug_entry.CvSignature == b'RSDS':
        signature = '{:08X}{:04X}{:04X}{:02X}{:02X}{}{:X}'.format(
                debug_entry.Signature_Data1, 
                debug_entry.Signature_Data2, 
                debug_entry.Signature_Data3,
                debug_entry.Signature_Data4,
                debug_entry.Signature_Data5,
                debug_entry.Signature_Data6.hex().upper(),
                debug_entry.Age)
    elif debug_entry.CvSignature == b'01BN':
        raise Exception('found')
        signature = f"{debug_entry.Signature:X}{debug_entry.Age:X}"
    else:
        raise UnsupportedDebugEntryTypeError(debug_entry.CvSignature)
    
    pdbfilename = debug_entry.PdbFileName
    
    # Remove trailing null-byte
    if pdbfilename[-1] == 0:
        pdbfilename = pdbfilename[:-1]
    
    return PdbInfo(signature, pdbfilename.decode())


async def download_pdb(pdbinfo: PdbInfo, pdbstore: Optional[str]=None) -> bytes:
    # Example:
    # https://msdl.microsoft.com/download/symbols/vcruntime140_1.amd64.pdb/9C85A7373CC2BC2A7AB9C9388952B8F81/vcruntime140_1.amd64.pdb
    
    if pdbstore is None:
        pdbstore = 'https://msdl.microsoft.com/download/symbols'

    # Remove trailing slash
    if pdbstore.endswith('/'):
        pdbstore = pdbstore[:-1]
    
    pdbbasename = pdbinfo.basename()
    url = f'{pdbstore}/{pdbbasename}/{pdbinfo.pdb_signature}/{pdbbasename}'

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 404:
                raise PdbNotFoundError()
            elif response.status == 200:
                return await response.read()
            else:
                raise UnexpectedReturnStatusError(response.status)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', type=str, required=True, help='Path to PE file')
    parser.add_argument('-s', '--store', type=str, help='PDB store URL')
    parser.add_argument('-n', '--no-download', help='No download. Only print PDB info.', action='store_true')
    parser.add_argument('-o', '--output', type=str, help='Output filepath')
    parser.add_argument('-d', '--output-dir', type=str, help='Output directory')
    args = parser.parse_args()

    # Read the file.
    try:
        with open(args.file, 'rb') as f:
            pe_data = f.read()
    except FileNotFoundError:
        parser.error(f'could not find file {args.file}')

    # Extract PDB info.
    try:
        pdbinfo = await extract_pdb_info(pe_data)
    except NoDebugEntryException:
        print('PE file does not contain a debug entry.')
        return
    except UnsupportedDebugEntryTypeError as e:
        print(f'PE file contains an unssupported debug entry type: {e.args[0]}')
        return

    print(f'PDB signature: {pdbinfo.pdb_signature}')
    print(f'PDB filename: {pdbinfo.pdbfilename}')

    if not args.no_download:
        # Download the PDB.
        try:
            pdb = await download_pdb(pdbinfo, pdbstore=args.store)
        except PdbNotFoundError:
            print('PDB store returned 404. PDB not found.')
            return
        except UnexpectedReturnStatusError as e:
            print(f'PDB store returned unexepected status code: {e.args[0]}')
            return

        # Determine the output file path.
        if args.output:
            filename = args.output
        else:
            filename = pdbinfo.basename()

        if args.output_dir:
            filepath = os.path.join(args.output_dir, filename)
        else:
            filepath = filename

        # Write the PDB.
        with open(filepath, 'wb') as f:
            f.write(pdb)
        
        print(f'PDB written to {filepath}')


if __name__ == '__main__':
    asyncio.run(main())