from __future__ import with_statement

import os, sys, errno, hashlib

from fuse import FUSE, FuseOSError, Operations
import base64
from Crypto import Random
from Crypto.Cipher import AES
import random, string

def randomword(length):
   return ''.join(random.choice(string.lowercase) for i in range(length))


class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class Passthrough(Operations):
    def __init__(self, root):
        self.root = root

    # Helpers
    # =======

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    def readdir(self, path, fh):
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        return os.open(full_path, os.O_WRONLY | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        str=os.read(fh, length)
        return cryObj.decrypt(str)

    def write(self, path, buf, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        buf=cryObj.encrypt(buf)
        return os.write(fh, buf)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        return self.flush(path, fh)


def createmount(mountpoint, root):
    FUSE(Passthrough(root), mountpoint, nothreads=True, foreground=True)

def createPassword():
    psswd=raw_input("Enter the new password: ").strip()
    if psswd == raw_input("Enter the new password again: ").strip():
        hash_obj=hashlib.md5(psswd)
        enc2Obj=AESCipher(psswd)
        cf=open("encry.txt",'w')
        pphrase=enc2Obj.encrypt(randomword(30))
        cf.write(pphrase)
        cf.close()
        f=open("key.txt",'w')
        f.write(hash_obj.hexdigest())
        f.close()
    else:
        print "Passwords don't match!"
        createPassword()

def checkPassword():
    f=open("key.txt",'r')
    key=f.read().strip()
    f.close()
    if key=="":
        createPassword()
        return checkPassword()
    else:
        psswd=raw_input("Enter the password: ").strip()
        hash_obj=hashlib.md5(psswd)
        if hash_obj.hexdigest()==key:
            return [True, psswd]
        else:
            return [False]

def changePassword():
    opsswd=raw_input("Enter the old password: ").strip()
    hash_obj= hashlib.md5(opsswd)
    f=open("key.txt",'r')
    key=f.read().strip()
    f.close()
    if hash_obj.hexdigest()==key:
        cf=open("encry.txt",'r')
        pphrase=cf.read().strip()
        cf.close()
        enc2Obj=AESCipher(opsswd)
        pphrase=enc2Obj.decrypt(pphrase)
        npsswd=raw_input("Enter the new password: ").strip()
        if npsswd == raw_input("Enter the new password again: ").strip():
            hash_obj= hashlib.md5(npsswd)
            f=open("key.txt",'w')
            f.write(hash_obj.hexdigest())
            f.close()
            enc2Obj=AESCipher(npsswd) 
            pphrase=enc2Obj.encrypt(pphrase)
            cf=open("encry.txt",'w')
            cf.write(pphrase)
            cf.close()
        else:
            print "Passwords don't match!"
            if raw_input("Do you want to try again? [y/n] ").strip() in 'yYy':
                changePassword()
    else:
        print "Wrong password"
        if raw_input("Do you want to try again [y/n] ").strip() in 'yYy':
            changePassword()


i=0
cryObj=None
while True:
    if i>3:
        print "Too many tries...Terminating Program."
        break
    passlist=checkPassword()
    if passlist[0]==True:
        if raw_input("Do you want to change password? [y/n] ").strip() in 'yYy':
            changePassword()
        cf=open("encry.txt",'r')
        pphrase=cf.read().strip()
        cf.close()
        enc2Obj=AESCipher(passlist[1])
        pphrase=enc2Obj.decrypt(pphrase)
        cryObj=AESCipher(pphrase)
        createmount(sys.argv[2], sys.argv[1])
    else:
        print "Wrong password"
