let SessionLoad = 1
let s:so_save = &g:so | let s:siso_save = &g:siso | setg so=0 siso=0 | setl so=-1 siso=-1
let v:this_session=expand("<sfile>:p")
silent only
silent tabonly
cd ~/.local/share/nvim/plugged/vim-obsession/plugin
if expand('%') == '' && !&modified && line('$') <= 1 && getline(1) == ''
  let s:wipebuf = bufnr('%')
endif
let s:shortmess_save = &shortmess
if &shortmess =~ 'A'
  set shortmess=aoOA
else
  set shortmess=aoO
endif
badd +1 ~/Projects/goblin
badd +50 ~/Projects/goblin/src/executable.cpp
badd +31 ~/Projects/goblin/include/loadable.hpp
badd +31 ~/Projects/goblin/include/executable.hpp
badd +207 ~/Projects/goblin/src/loadable.cpp
badd +1 ~/Projects/goblin/terminal
badd +160 term://~/Projects/goblin//21293:/bin/bash
badd +1 ~/Projects/goblin/src/loadable.hpp
badd +2 ~/Projects/goblin/src/goblin.cpp
badd +136 term://~/Projects/goblin//22580:/bin/bash
badd +23 ~/Projects/goblin/src/elf_file.cpp
badd +14 ~/Projects/goblin/src/x86_64/asm.S
badd +12 ~/Projects/goblin/makefile
badd +0 term://~/Projects/goblin//31135:/bin/bash
badd +2 ~/Projects/goblin/include/tls.hpp
argglobal
%argdel
$argadd NvimTree_1
set stal=2
tabnew +setlocal\ bufhidden=wipe
tabrewind
edit ~/Projects/goblin/src/x86_64/asm.S
let s:save_splitbelow = &splitbelow
let s:save_splitright = &splitright
set splitbelow splitright
wincmd _ | wincmd |
split
1wincmd k
wincmd w
let &splitbelow = s:save_splitbelow
let &splitright = s:save_splitright
wincmd t
let s:save_winminheight = &winminheight
let s:save_winminwidth = &winminwidth
set winminheight=0
set winheight=1
set winminwidth=0
set winwidth=1
wincmd =
argglobal
balt ~/Projects/goblin/src/executable.cpp
setlocal fdm=manual
setlocal fde=0
setlocal fmr={{{,}}}
setlocal fdi=#
setlocal fdl=0
setlocal fml=1
setlocal fdn=20
setlocal fen
silent! normal! zE
let &fdl = &fdl
let s:l = 6 - ((5 * winheight(0) + 8) / 16)
if s:l < 1 | let s:l = 1 | endif
keepjumps exe s:l
normal! zt
keepjumps 6
normal! 0
lcd ~/Projects/goblin
wincmd w
argglobal
if bufexists(fnamemodify("~/Projects/goblin/src/executable.cpp", ":p")) | buffer ~/Projects/goblin/src/executable.cpp | else | edit ~/Projects/goblin/src/executable.cpp | endif
if &buftype ==# 'terminal'
  silent file ~/Projects/goblin/src/executable.cpp
endif
balt ~/Projects/goblin/include/executable.hpp
setlocal fdm=manual
setlocal fde=0
setlocal fmr={{{,}}}
setlocal fdi=#
setlocal fdl=0
setlocal fml=1
setlocal fdn=20
setlocal fen
silent! normal! zE
let &fdl = &fdl
let s:l = 50 - ((12 * winheight(0) + 12) / 25)
if s:l < 1 | let s:l = 1 | endif
keepjumps exe s:l
normal! zt
keepjumps 50
normal! 09|
lcd ~/Projects/goblin
wincmd w
2wincmd w
wincmd =
tabnext
argglobal
if bufexists(fnamemodify("term://~/Projects/goblin//31135:/bin/bash", ":p")) | buffer term://~/Projects/goblin//31135:/bin/bash | else | edit term://~/Projects/goblin//31135:/bin/bash | endif
if &buftype ==# 'terminal'
  silent file term://~/Projects/goblin//31135:/bin/bash
endif
balt ~/Projects/goblin/terminal
setlocal fdm=manual
setlocal fde=0
setlocal fmr={{{,}}}
setlocal fdi=#
setlocal fdl=0
setlocal fml=1
setlocal fdn=20
setlocal fen
let s:l = 159 - ((0 * winheight(0) + 21) / 42)
if s:l < 1 | let s:l = 1 | endif
keepjumps exe s:l
normal! zt
keepjumps 159
normal! 034|
lcd ~/Projects/goblin
tabnext 1
set stal=1
if exists('s:wipebuf') && len(win_findbuf(s:wipebuf)) == 0 && getbufvar(s:wipebuf, '&buftype') isnot# 'terminal'
  silent exe 'bwipe ' . s:wipebuf
endif
unlet! s:wipebuf
set winheight=1 winwidth=20
let &shortmess = s:shortmess_save
let s:sx = expand("<sfile>:p:r")."x.vim"
if filereadable(s:sx)
  exe "source " . fnameescape(s:sx)
endif
let &g:so = s:so_save | let &g:siso = s:siso_save
set hlsearch
let g:this_session = v:this_session
let g:this_obsession = v:this_session
doautoall SessionLoadPost
unlet SessionLoad
" vim: set ft=vim :
