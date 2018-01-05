package=librustzcash
$(package)_version=0.1
$(package)_download_path=https://github.com/zcash/$(package)/archive/
$(package)_file_name=$(package)-$($(package)_git_commit).tar.gz
$(package)_download_file=$($(package)_git_commit).tar.gz
$(package)_sha256_hash=ac55aa3299b09dfc3a12461fb23a17b3f258cf4bd14e615b3cd8beae14379ea3
$(package)_git_commit=c824e610322823b25198bb0c7effb3a7f020c3d4
$(package)_dependencies=rust

define $(package)_build_cmds
  cargo build --release
endef

define $(package)_stage_cmds
  mkdir $($(package)_staging_dir)$(host_prefix)/lib/ && \
  mkdir $($(package)_staging_dir)$(host_prefix)/include/ && \
  cp target/release/librustzcash.a $($(package)_staging_dir)$(host_prefix)/lib/ && \
  cp include/librustzcash.h $($(package)_staging_dir)$(host_prefix)/include/
endef
