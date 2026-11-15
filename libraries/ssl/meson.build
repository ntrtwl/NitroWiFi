libssl = library('ssl',
    dependencies: [nitrosdk_dep],
    include_directories: nitrowifi_includes,
    pic: false,
    sources: files(
        'src/ssl.c',
        'src/md5.c',
        'src/sha1.c',
        'src/rc4.c',
        'src/biginteger.c'
    )
)

nitrowifi_libs += libssl
