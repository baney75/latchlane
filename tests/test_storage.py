import os
from pathlib import Path
import pytest
from latchlane.vault import private_directory,private_read,atomic_write,VaultError

def test_filesystem_boundaries(tmp_path):
    private_directory(tmp_path)
    p=tmp_path/'data';atomic_write(p,b'fixture');assert private_read(p)==b'fixture'
    if os.name!='nt':
        assert p.stat().st_mode & 0o777==0o600
        p.chmod(0o644)
        with pytest.raises(VaultError):private_read(p)
        p.chmod(0o600)
        link=tmp_path/'link';link.symlink_to(p)
        with pytest.raises((VaultError,OSError)):private_read(link)
        with pytest.raises(VaultError):atomic_write(link,b'bad')
        d=tmp_path/'directory-link';d.symlink_to(tmp_path,target_is_directory=True)
        with pytest.raises(VaultError):private_directory(d)
