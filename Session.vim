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
badd +20 ~/Projects/goblin/src/executable.cpp
badd +71 ~/Projects/goblin/include/loadable.hpp
badd +22 ~/Projects/goblin/include/executable.hpp
badd +203 ~/Projects/goblin/src/loadable.cpp
badd +1 ~/Projects/goblin/terminal
badd +160 term://~/Projects/goblin//21293:/bin/bash
badd +1 ~/Projects/goblin/src/loadable.hpp
badd +6 ~/Projects/goblin/src/goblin.cpp
badd +136 term://~/Projects/goblin//22580:/bin/bash
badd +23 ~/Projects/goblin/src/elf_file.cpp
badd +6 ~/Projects/goblin/src/x86_64/asm.S
badd +12 ~/Projects/goblin/makefile
badd +20 ~/Projects/goblin/README.md
badd +1 ~/Projects/goblin/tests/tlstest.c
badd +1 ~/Projects/goblin/tests/tlstest.S
badd +22 ~/Projects/goblin/tls.S
badd +281 term://~/Projects/goblin//19654:/bin/bash
badd +0 term://~/Projects/goblin//19747:/bin/bash
argglobal
%argdel
$argadd NvimTree_1
set stal=2
tabnew +setlocal\ bufhidden=wipe
tabrewind
edit ~/Projects/goblin/makefile
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
balt ~/Projects/goblin/src/loadable.cpp
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
let s:l = 5 - ((4 * winheight(0) + 12) / 25)
if s:l < 1 | let s:l = 1 | endif
keepjumps exe s:l
normal! zt
keepjumps 5
normal! 047|
lcd ~/Projects/goblin
wincmd w
argglobal
if bufexists(fnamemodify("~/Projects/goblin/tls.S", ":p")) | buffer ~/Projects/goblin/tls.S | else | edit ~/Projects/goblin/tls.S | endif
if &buftype ==# 'terminal'
  silent file ~/Projects/goblin/tls.S
endif
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
let s:l = 22 - ((9 * winheight(0) + 9) / 18)
if s:l < 1 | let s:l = 1 | endif
keepjumps exe s:l
normal! zt
keepjumps 22
normal! 029|
lcd ~/Projects/goblin
wincmd w
2wincmd w
wincmd =
tabnext
argglobal
if bufexists(fnamemodify("term://~/Projects/goblin//19747:/bin/bash", ":p")) | buffer term://~/Projects/goblin//19747:/bin/bash | else | edit term://~/Projects/goblin//19747:/bin/bash | endif
if &buftype ==# 'terminal'
  silent file term://~/Projects/goblin//19747:/bin/bash
endif
balt term://~/Projects/goblin//19654:/bin/bash
setlocal fdm=manual
setlocal fde=0
setlocal fmr={{{,}}}
setlocal fdi=#
setlocal fdl=0
setlocal fml=1
setlocal fdn=20
setlocal fen
let s:l = 44 - ((43 * winheight(0) + 22) / 44)
if s:l < 1 | let s:l = 1 | endif
keepjumps exe s:l
normal! zt
keepjumps 44
normal! 0
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
