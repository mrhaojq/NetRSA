/*
This file in the main entry point for defining grunt tasks and using grunt plugins.
Click here to learn more. http://go.microsoft.com/fwlink/?LinkID=513275&clcid=0x409
*/
module.exports = function (grunt) {
    grunt.initConfig({

        //拷贝文件
        copy: {
            expand: true,                           //展开
            cwd: 'content/fonts/',                  //改变当前路径
            src: ['**'],                            //匹配文件的正则表达式
            dest: '<%= path.dest %>/fonts/',        //
            flatten: false
        }
    });
};