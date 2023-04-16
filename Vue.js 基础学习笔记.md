# Vue.js 学习笔记

Vue3 是一种流行的 JavaScript 框架，用于构建现代化的 Web 应用程序。Vue3 相对于 Vue2 来说，有许多新的特性和改进，包括更好的性能、更好的 TypeScript 支持、更好的可维护性等等。

Vue3相比jQuery的区别主要在于以下几点：

1. 声明式渲染

Vue3提供了声明式渲染，将数据与DOM进行绑定，当数据发生变化时，Vue会自动更新DOM，也就是说，Vue在操作数据时不再需要进行DOM操作。相比较于jQuery的命令式渲染，声明式渲染更加简洁和易于维护。

​	2.组件化开发

Vue3支持组件化开发，使得我们可以将一个页面拆分成多个组件进行开发和维护。组件化开发提高了代码的可复用性和可维护性。而jQuery则需要手动进行DOM操作，很难实现组件化开发。

​	3.响应式数据

Vue3提供了响应式数据，当数据发生变化时，Vue会自动更新DOM。而jQuery需要手动进行数据绑定和DOM操作，代码量较大，也容易出错。

## Vue.js目录构成

当你创建了一个 Vue 3 项目时，以下是项目文件中各个文件的作用：

**public/index.html:** 该文件是您的应用程序的 HTML 模板，其中包含一个根元素，该元素将用于**挂载**您的 Vue 应用程序。

> 在 Vue 应用程序中，挂载是指将 Vue 实例连接到实际的 HTML 页面上。在 Vue 中，您需要在 HTML 中指定一个根元素，该元素将成为 Vue 应用程序的容器。通过将 Vue 实例挂载到根元素上，Vue 将能够动态地更新根元素及其子元素的内容。
>
> 在 Vue 3 中，您可以使用 `$mount` 方法将 Vue 实例挂载到根元素上。
>
> 例如，在您的 `main.js` 文件中，您可以使用以下代码创建并挂载一个新的 Vue 实例：
>
> ```
> import { createApp } from 'vue'
> import App from './App.vue'
> 
> createApp(App).mount('#app')
> ```
>
> 在该代码中，`createApp` 方法将创建一个新的 Vue 实例，并将其传递给 `App` 组件。然后，`mount` 方法将 Vue 实例挂载到具有 `id` 为 `app` 的元素上。
>
> 因此，"挂载您的 Vue 应用程序"的意思是将 Vue 实例连接到 HTML 页面上，以便 Vue 可以动态地更新页面内容，并响应用户的输入和操作。

**src/main.js:** 该文件是您的应用程序的入口文件。在该文件中，您将创建您的 Vue 实例，并将其挂载到根元素上。

**src/App.vue:** 该文件是您的应用程序的根组件。在该文件中，您可以定义应用程序的布局和样式，并将其他组件插入到该组件中。

**src/components/:** 该文件夹包含您的应用程序的所有组件。在该文件夹中，您可以创建和管理您的组件。

**src/assets/:** 该文件夹包含您的应用程序的静态资源，如图像、样式表和字体文件。

**src/router/:** 该文件夹包含您的应用程序的路由配置（如果您的项目使用了）。在该文件夹中，您可以定义应用程序的路由，并将路由映射到组件。

**src/store/:** 该文件夹包含您的应用程序的状态管理配置。在该文件夹中，您可以定义应用程序的状态和操作，并将其用于组件中。

**src/main.css:** 该文件是您的应用程序的全局 CSS 样式表。在该文件中，您可以定义应用程序的全局样式。

**babel.config.js:** 该文件是 Babel 的配置文件。在该文件中，您可以定义 Babel 的插件和预设，以便您的应用程序可以使用最新的 JavaScript 特性。

**package.json:** 该文件是您的应用程序的包管理配置文件。在该文件中，您可以定义应用程序的依赖项、脚本和其他元数据。

**package-lock.json:** 该文件是您的应用程序的依赖项锁定文件。在该文件中，您可以确保您的应用程序的依赖项版本不会发生变化。

**README.md:** 该文件是您的应用程序的说明文档。在该文件中，您可以提供关于您的应用程序的信息和文档。

### Parsing error: No Babel config file detected for ’......‘：

> 在package.json文件下找到"parserOptions"，添加："requireConfigFile" : false 即可
>
> 如下：
>
> "parserOptions": {
>
> ```javascript
>   "parser": "@babel/eslint-parser",
>   "requireConfigFile" : false
> },
> ```

## Vue.js基础

推荐在学习**Vue3**前至少先学会**Vue2.x的基本知识**以快速上手：

[Vue2.x 前端四小时入门]: https://www.bilibili.com/video/BV12J411m7MG

以下是Vue的基础知识点：

​	1.组件：在项目中，组件可以被用来封装应用中的特定功能和样式，实现组件的复用和解耦。比如可以将页面中的头部、底部、导航栏等内容封装成组件，在不同的页面中进行复用。

​	2.模板语法：在项目中，可以使用模板语法来编写组件模板，实现组件的渲染。比如可以使用 v-if、v-for 等指令来根据数据状态控制组件的渲染。

​	3.数据绑定：在项目中，数据绑定可以用来实现响应式的 UI 更新。比如可以将表单数据与组件进行绑定，实现表单数据的同步更新。

​	4.计算属性和侦听器：在项目中，计算属性和侦听器可以用来处理复杂的数据逻辑。比如可以使用计算属性来计算表单数据的合法性，使用侦听器来监听表单数据的变化并进行相应的操作。

​	5.条件渲染和列表渲染：在项目中，可以使用条件渲染和列表渲染来根据数据状态控制组件的渲染。比如可以根据登录状态来显示不同的导航栏内容，使用 v-for 指令来渲染列表数据。

​	6.生命周期：在项目中，生命周期可以用来执行不同阶段的操作。比如可以在 created 钩子中进行数据初始化，在 mounted 钩子中进行组件的渲染等。	

​	7.组件通信：在项目中，可以使用组件通信来实现组件之间的数据传递和交互。比如可以使用 props 来将数据从父组件传递给子组件，使用事件来在组件之间进行通信。

​	8.路由：在项目中，可以使用路由来实现单页应用的导航和页面切换。比如可以通过路由来实现不同页面之间的跳转和参数传递。

​	9.Vuex：在项目中，可以使用 Vuex 来统一管理应用的数据状态。比如可以将登录状态、用户信息等数据存储在 Vuex 中，实现不同组件之间的数据共享和交互。

​	10.插件和指令：在项目中，可以使用插件和指令来扩展 Vue3 的功能，实现特定的需求和功能。比如可以使用 moment.js 插件来处理日期时间格式化，使用 v-scroll 指令来实现页面滚动监听等。

## 基础学习

### 组件

在 Vue3 中，组件是最重要的概念之一。它可以让我们将一个页面拆分成多个独立的部分，每个部分都有自己的数据和行为。这样做的好处是，我们可以更好地管理和维护代码，同时也可以让页面更加灵活和可复用。

> 举个例子，假设我们正在开发一个在线商城的网站，我们可以将页面拆分成多个组件，例如：
>
> - 商品列表组件：展示所有商品的列表，包括商品的名称、价格、图片等信息。
> - 购物车组件：展示用户已经选择的商品列表，包括商品的数量、价格等信息。
> - 搜索框组件：允许用户输入关键词搜索商品。
> - 商品详情组件：展示某个商品的详细信息，包括商品的名称、价格、图片、描述等信息。
>
> 这些组件可以相互组合，形成一个完整的商城网站。例如，我们可以在商品列表组件中引用搜索框组件，让用户可以通过搜索框来查找商品。我们还可以在商品列表组件和商品详情组件中引用购物车组件，让用户可以将商品添加到购物车中。
>
> 通过将页面拆分成多个组件，我们可以更好地组织代码，让每个组件都变得更加简单和易于维护。同时，我们还可以更好地复用组件，将它们应用到不同的页面中，提高代码的重用性和开发效率。

定义一个组件可以使用 `defineComponent` 函数，如下所示：

```vue
<template>
  <div>
    <h1>{{ title }}</h1>
    <p>{{ content }}</p>
  </div>
</template>

<script>
import { defineComponent } from 'vue'

export default defineComponent({
  props: {
    title: {
      type: String,
      required: true
    },
    content: {
      type: String,
      required: true
    }
  }
})
</script>
```

<div align="center">Test_Component.vue</div>

在上面的代码中，我们定义了一个带有 `title` 和 `content` 两个属性的组件，并使用 `defineComponent` 函数来定义组件。`props` 是组件实例的可配置的属性。当一个值传递给 `props` 时,它会变成组件实例的一个属性。`props` 允许你在组件上进行配置,就像你在 DOM 元素上设置属性一样。这让你可以在组件内部保持很简单的状态,同时在组件的不同实例之间传递自定义的值。

然后在App.vue中使用该组件：

```vue
<template>
  <div>
    <Test_Component
      :title="'Hello, World!'"
      :content="'This is a Vue component.'"
    />
  </div>
</template>

<script>
import { defineComponent } from 'vue'
import Test_Component from './components/Test_Component.vue'

export default defineComponent({
  components: {
    Test_Component
  }
})
</script>
```

<div align="center">App.vue</div>

在该代码中，我们在模板中使用了 `<Test_Component>` 元素来呈现 `Test_Component` 组件，并传递了 `title` 和 `content` 属性。在 `<script>` 标记中，我们导入了 `Test_Component.vue` 组件，并在 `components` 选项中将其注册为名为 `Test_Component` 的组件。最后，我们使用 `defineComponent` 函数来定义 `App` 组件。请注意，我们使用了 `v-bind` 缩写语法 `:` 来将属性绑定到表达式。

### 模板语法

在 Vue3 中，我们可以使用模板语法来编写页面。模板语法类似于 HTML，但是它可以引用组件中的数据和方法，让页面变得更加动态和交互。下面是一个简单的例子：

```vue
<template>
  <div>
    <h1>{{ title }}</h1>
    <ul>
      <li v-for="item in list" :key="item.id">{{ item.text }}</li>
    </ul>
  </div>
</template>

<script>
import { defineComponent } from 'vue'

export default defineComponent({
  data() {
    return {
      title: '我的待办事项',
      list: [
        { id: 1, text: '学习Vue3' },
        { id: 2, text: '学习TypeScript' },
        { id: 3, text: '写一个Vue3应用' }
      ]
    }
  }
})
</script>
```

<div align="center">Template_syntax.vue</div>

在上面的代码中，我们使用了 `v-for` 指令来循环渲染待办事项列表。为了便利，我们直接在App.vue续接代码:

```vue
<template>
  <div>
    <Test_Component
      :title="'Hello, World!'"
      :content="'This is a Vue component.'"
    />
  </div>
  <div>
    <Template_syntax/>
  </div>
</template>

<script>
import { defineComponent } from 'vue'
import Test_Component from './components/Test_Component.vue'
import Template_syntax from './components/Template_syntax.vue'
export default defineComponent({
  components: {
    Test_Component,
    Template_syntax
  }
})
</script>
```

<div align="center">App.vue</div>

在该代码中，我们导入了 `Template_syntax.vue` 文件，并在 `components` 选项中将其注册为名为 `Template_syntax` 的组件。然后，我们在模板中使用 `<Template_syntax>` 元素来呈现该组件。

当渲染 `Template_syntax` 组件时，Vue 将会自动将组件的 `title` 和 `list` 属性传递给组件 ( 这些属性可以在组件中使用 `this.$props` 来访问 )

### 数据绑定

在 Vue3 中，我们可以使用数据绑定来让页面中的数据和组件中的数据保持同步。这意味着，当组件中的数据发生变化时，页面中的数据也会自动更新，反之亦然。通过使用数据绑定，我们可以让页面和组件中的数据保持同步，避免了手动更新页面的繁琐操作。同时，我们还可以使用计算属性和监视器等特性来实现更加复杂的数据处理和操作，让应用程序变得更加强大和灵活。下面是一个简单的例子：

```vue
<template>
    <div>
        <p>{{ message }}</p>
        <input v-model="message" />
    </div>
</template>

<script>
import { defineComponent } from 'vue';
export default defineComponent({
    data(){
        return{
            message:'Hello Vue3!'
        }
    }
})
</script>
```

<div align="center">Data_binding.vue</div>

在上面的代码中，我们使用了 `v-model` 指令来将输入框的值与 `message` 数据进行绑定，从而实现输入框的内容同步更新到页面上。该部分省略App.vue注册组件步骤，操作与 “2” 相同。 

### 计算属性和侦听器

在 Vue3 中，可以使用计算属性处理复杂的数据逻辑。

> 举个例子，假设我们正在开发一个在线游戏的网站，我们可以使用计算属性来计算玩家的等级。我们通过计算属性 `playerLevel` 来根据 `player.score` 的值计算玩家的等级。这样，当玩家的得分发生变化时，等级也会自动更新。

`computed` 是一种用于基于已有数据计算衍生数据的工具。它会在依赖的数据发生变化时自动更新，但只有在需要时才会计算，而不是每次都重新计算。因此，`computed` 适合用于需要依赖其他数据计算的场景，例如格式化数据、过滤列表、计算总和等。下面是一个简单的例子：

```vue
<template>
    <div>
        <p>{{ fullName }}</p>
        <input v-model="firstName" /><br/>
        <input v-model="lastName" />
    </div>
</template>

<script>
import { defineComponent,computed} from 'vue';
export default defineComponent({
    data(){
        return{
            firstName:'',
            lastName:''
        }
    },
    computed:{
        fullName(){
            return this.firstName + ' ' + this.lastName
        }
    },
})
</script>
```

<div align="center">Test_Cpmpute.vue</div>

在上面的代码中，我们定义了一个计算属性 `fullName`，用来计算 `firstName` 和 `lastName` 的合并结果。当 `firstName` 或 `lastName` 变化时，`fullName` 会自动更新，从而实现数据的同步。同样，我们省略App.vue注册组件步骤，因为该部分操作与 “2” 相同。

#### **'XXX‘ is defined but never used：**

> 找到`package.json`文件，然后在`"rules"`配置项添加：
>
> ```javascript
>"rules": {
>    "no-unused-vars":"off"
>  }
>    ```
>    
> ​	最后使用`npm run serve`重新运行项目



在 Vue3 中，也可以使用侦听器处理复杂的数据逻辑。

> 举个例子，假设我们正在开发一个在线音乐播放器，我们可以使用侦听器来监听歌曲的播放状态。我们使用侦听器 `watch` 来监听 `isPlaying` 数据的变化，并在数据发生变化时执行一些操作。这样，当用户点击播放按钮时，歌曲会播放或暂停，并且控制台会输出相应的信息。

`watch` 是一种用于监听数据变化并在数据变化时执行副作用操作的工具。它会在数据发生变化时立即执行相应的副作用操作，例如发送网络请求、更新 DOM、触发其他操作等。下面是一个简单的例子：

```vue
<template>
    <div>
        <p>监听</p>
        <p>{{ fullName }}</p>
        <input v-model="firstName" /><br/>
        <input v-model="lastName" />
    </div>
    <hr/>
</template>
<script>
import { defineComponent,watch } from 'vue';
export default defineComponent({
  data() {
    return {
      firstName: '',
      lastName: '',
      fullName: ''
    }
  },
  watch: {
    firstName(newVal, oldVal) {
      this.updateFullName(newVal, this.lastName, oldVal);
    },
    lastName(newVal, oldVal) {
      this.updateFullName(this.firstName, newVal, oldVal);
    }
  },
  methods: {
    updateFullName(firstName, lastName, oldFullName) {
      const newFullName = `${firstName} ${lastName}`;
      if (newFullName !== oldFullName) {
        this.fullName = newFullName;
        console.log(`fullName changed from ${oldFullName} to ${newFullName}`);
      }
    }
  }
})
</script>
```

<div align="center">Test_Listen.vue</div>

在这个示例中，我们在 `watch` 监听器的回调函数中使用了 `oldVal` 参数，并将其传递给了`updateFullName` 方法。在 `updateFullName` 方法中，我们比较了新的完整名字和旧的完整名字，如果发现它们不相同，则更新 `fullName` 数据属性并输出一条日志。这样，在每次更新 `fullName` 数据属性时，我们都可以记录旧值和新值之间的变化，从而更好地了解数据的变化情况。同样，我们省略App.vue注册组件步骤，因为该部分操作与 “2” 相同。

### 条件渲染和列表渲染

在 Vue3 中，可以使用条件渲染和列表渲染来根据数据状态控制组件的渲染：

条件渲染 - 使用 v-if 和 v-else 指令来根据条件来渲染或跳过元素的渲染。例如：

```vue
<span v-if="someCondition">Show this</span>
<span v-else>Show this instead</span>
```

列表渲染 - 这使用 v-for 指令基于数组数据来渲染一个列表。例如：

```vue
<ul> <li v-for="item in items">{{ item }}</li> </ul>
```

这两种技术都可以根据数据状态动态生成页面的一部分。条件渲染用于根据True/False条件包括或排除元素。列表渲染用于遍历数组/对象并为每个项渲染一个元素。它们都是非常强大的,允许你基于组件数据动态生成复杂的模板,而不必手动管理所有可能的情况。

下面是一个简单的例子：

```vue
<template>
    <div>
        <button @click="show = !show">
        {{ show ?'隐藏' : '显示' }}
        </button>
        <ul v-if="show">
            <li v-for="item in list" :key="item.id">
                {{ item.text }}
            </li>
        </ul>
    </div>
    <hr/>
</template>

<script>
    import { defineComponent } from 'vue';
    export default defineComponent({
        data(){
            return{
                show:true,
                list:[
                    {id:1,text:'学习Vue3'},
                    {id:2,text:'学习TypeScript'},
                    {id:3,text:'写一个Vue3应用'}
                ]
            }
        }
    })
</script>
```

在上面的代码中，我们使用了 `v-if  ` 和 `v-for` 指令来实现根据数据状态控制组件的渲染和循环渲染列表的功能。同样，我们省略App.vue注册组件步骤，因为该部分操作与 “2” 相同。

### 生命周期

在 Vue3 中，可以使用生命周期函数来执行不同阶段的操作。Vue 的生命周期钩子是一系列函数,它允许你在 Vue 实例的生命周期的不同阶段执行自定义代码。

例如:

`created` - 实例创建完成后调用
`mounted` - 实例挂载到 DOM 后调用
`updated` - 实例更新后调用 (due to data change)
`unmounted` - 实例从 DOM 中移除后调用

......

这些钩子允许你在适当的时候执行初始化代码,响应 DOM 事件,调用服务端 API,监听组件之间的依赖关系等。

> 比如，我们在开发一个在线聊天室的应用程序时，我们可以使用生命周期钩子来监听用户的登录状态，在用户登录时自动连接服务器，当用户退出时自动断开连接。

具体来说，Vue 组件的生命周期可以分为以下几个阶段：

- 创建阶段：组件被创建，数据被初始化。
- 挂载阶段：组件被添加到页面中，数据开始渲染。
- 更新阶段：组件的数据发生变化，更新页面中的内容。
- 卸载阶段：组件被从页面中移除，数据被清除。

在每个阶段，Vue 都会触发一系列的生命周期钩子，我们可以在这些钩子中执行相应的操作和处理。比如，在创建阶段，我们可以使用 `created` 钩子来执行一些初始化操作；在更新阶段，我们可以使用 `updated` 钩子来监听数据的变化并更新页面上的内容。

生命周期钩子使你的代码和 Vue 实例生命周期同步,是组件逻辑的强大策略之一。

下面是一个简单的例子：

```vue
<template>
    <div>
        <p>{{ message }}</p>
    </div>
</template>

<script>
    import { defineComponent } from 'vue';
    export default defineComponent({
        data(){
            return{
                message:'Hello Vue3!'
            }
        },
        created(){
            console.log('组件创建完成')
        },
        mounted(){
            console.log('组件挂载完成')
        }
    })
</script>
```

<div align="center">Life_cycle.vue</div>

在上面的代码中，我们使用了 `created` 和 `mounted` 钩子函数来分别在组件创建和挂载时执行操作。同样，我们省略App.vue注册组件步骤，因为该部分操作与 “2” 相同。

### 组件通信

在 Vue3 中，可以使用组件通信来实现组件之间的数据传递和交互。

> 比如，我们在开发一个在线购物网站时，我们可以使用组件通信来实现购物车功能。我们可以把商品列表和购物车组件分别制作成不同的组件，然后使用组件通信来实现商品的添加、删除、数量的修改等操作。

Vue 组件可以使用以下方法来通信：

`Props` - 由父组件传到子组件的数据
`Events` - 由子组件传到父组件的消息
`Slots` - 由父组件传到子组件的内容
`Global Events` - 打乱组件层级的通信
`Provide/Inject` - 祖先组件向后代组件传递数据

`Props` 是最常用的方式，它像函数的参数一样，允许父组件传递数据给子组件：

<div align="center">Parent.vue</div>

```vue
<Child :msg="message" />
```

<div align="center">Child.vue</div>
```vue
props: ['msg']
```



`Events` 用于子组件触发父组件中的回调:

<div align="center">Child.vue</div>
```vue
this.$emit('child-event')
```

<div align="center">Parent.vue</div>
```vue
<Child @child-event="handleEvent" />

methods: {
handleEvent() {
// Handle event
}
}
```

Slots，Provide/Inject 和 Global Events 有一些不同的用例，而 Props 和 Events 是最常见和最有用的组件通信方法。

下面是一个简单的例子：

```vue
<template>
    <div>
        <p>计数器:{{ count }}</p>
        <button @click="$emit('increment')">
            增加
        </button>
    </div>
</template>

<script>
    import { defineComponent } from 'vue';
    export default defineComponent({
        props:{
            count:{
                type:Number,
                required:true
            }
        }
    })
</script>
```

<div align="center">Test_Child.vue</div>

```vue
<template>
    <div>
        <p>{{ message }}</p>
        <Test_Chlid :count="count" @increment="increment"/>
    </div>
    <hr/>
</template>

<script>
    import { defineComponent } from 'vue';
    import Test_Chlid from './Test_Child.vue'
    export default defineComponent({
        data(){
            return{
                message:'组件通信',
                count:0
            }
        },
        components:{
            Test_Chlid
        },
        methods:{
            increment(){
                this.count++
            }
        }
    })
</script>

```

<div align="center">Test_Parent.vue</div>

在上面的代码中，我们使用了 `props` 和 `$emit` 方法来实现父子组件之间的数据传递和事件监听。父组件将 `count` 数据通过 `props` 传递给子组件，子组件通过 `$emit` 方法触发 `increment` 事件，从而实现父组件中的 `count` 数据增加的功能。

> @click - 点击元素时
> $emit - 发出一个事件
> ('increment') - 事件名为 increment
>
>  `@click="$emit('increment')"`意味着"点击元素时触发 `increment` 事件"。
> 然后，Parent 组件设置`count`绑定子组件的`count`，同时监听`increments` 事件  `@increment="increment"`，所以当 Child 触发 `increment` 事件时，`increment` 方法会运行。
> 这是组件之间进行事件通信的常见模式 - 子组件(事件发射器)触发一个事件,父组件(事件监听器)对此作出响应。

### 路由

**路由**是 Web 开发中的一种技术,它允许你定义应用程序中的路径/URL,并将它们连接到特定的内容/功能。
一些关于路由的关键点：

- 它允许你创建 RESTful、可读的 URL
- 它将 URL 与应用程序的物理文件结构脱钩
- 它使你能够将 URL 书签到应用程序中的特定内容/状态
- 它允许后退和前进按钮工作,以及正确的书签/共享 URL
- 它为 SEO (搜索引擎可以更好地爬取你的站点/应用)铺平道路

所以路由是构建 Web 应用程序的关键概念，它允许实现更好的用户体验和优化。Vue Router 是 Vue.js 的官方路由，它提供所有上述功能及更多功能。

Vue 3 中的路由意味着：

- Vue.js 的官方路由
- 与 Vue 深度集成(使用相同的选项 API 格式等)
- 路由匹配功能(动态片段、嵌套路由等)
- 编程导航(通过 router.push()、router.replace()等)
- 路由组件的懒加载
- 细粒度导航控制(命令式的、重定向、别名等)
- 路由 Props 和作用域插槽
- 强大的预导航守卫(全局的、每个路由的、组件内的)
- 细粒度滚动行为控制

​		......

在 Vue3 中，可以使用 `Vue Router` 来实现路由功能。`Vue Router` 提供了路由配置、路由跳转、路由守卫等功能，可以帮助开发人员更好地管理前端路由。下面是一个简单的例子：

我们首先确定两个路径，其中`/`代表home组件的路径，`/about`代表about组件的路径，然后分别创建这两个组件。

```vue
<template>
    <div>
      <h1>Home Page</h1>
      <p>{{ message }}</p>
      <router-link to="/about">Go to About Page</router-link>
    </div>
  </template>

  <script>
  import { defineComponent } from 'vue';
  export default defineComponent ({
    data() {
      return {
        message: 'Welcome to the Home Page!'
      }
    }
  })
  </script>
```

<div align="center">Test_Home.vue</div>

```vue
<template>
    <div>
      <h1>About Page</h1>
      <p>{{ message }}</p>
      <router-link to="/">Go to Home Page</router-link>
    </div>
  </template>
  <script>
  import { defineComponent } from 'vue';
  export default defineComponent ({
    data() {
      return {
        message: 'Welcome to the About Page!'
      }
    }
  })
  </script>
```

<div align="center">Test_About.vue</div>

这两个组件旨在实现一个点击文字链接互相跳转的功能，接下来我们就可以来配置这两个组件的路由。

使用`vue Router`前需要先安装好：`npm install vue-router@next`，然后在根目录创建`router.js`文件（如果项目没有自动生成），然后配置路由：

```javascript
import{ createRouter,createWebHistory} from 'vue-router'
import Test_Home from './src/components/Test_Home.vue'
import Test_About from './src/components/Test_About.vue'

const routes = [
    {
        path:'/',
        name:'home',
        component:Test_Home
    },
    {
        path:'/about',
        name:'about',
        component:Test_About
    }
]

const router = createRouter({
    history:createWebHistory(),
    routes
})

export default router
```

<div align="center">router.js</div>

这段代码是使用 `Vue Router` 创建了一个路由实例，并定义了两个路由路径 `/` 和 `/about`。其中，`createRouter` 方法用于创建路由实例，`createWebHistory` 方法用于创建浏览器历史记录管理实例。

接下来到`main.js`中注册路由：

```vue
import router from '../router'
createApp(App).use(router).mount('#app')
```

<div align="center">main.js</div>

最后在`App.vue`组件的模板中添加`<router-view/>`标签。

> 在 `Vue Router` 中，使用 `<router-view></router-view>` 标签是为了实现路由懒加载和路由嵌套功能。
>
> 当用户访问一个路由路径时，如果该路由路径对应的组件使用了 `<router-view></router-view>` 标签，那么 `Vue Router` 会根据路由路径自动渲染对应的组件，并将组件插入到 `<router-view></router-view>` 标签的位置。这样，就实现了路由动态渲染的功能。
>
> 同时，使用 `<router-view></router-view>` 标签还可以实现路由嵌套的功能。即在一个路由路径下，再嵌套其他路由路径。例如，在一个父级路由路径下，可以嵌套多个子级路由路径，每个子级路由路径对应一个组件，并使用 `<router-view></router-view>` 标签进行渲染。
>
> 因此，如果要使用 `Vue Router` 实现路由功能，就必须在组件中使用 `<router-view></router-view>` 标签，否则路由功能将无法正常工作。

#### 路由传参

传入一个对象：

```js
 path:'/updatafile/:row',
        name:'UpdataFile',
        component:() => import('@/components/UpdataFile.vue'),
```

需将其序列化

```vue
<router-link :to="'/updatafile/' + JSON.stringify(row)">
```

传入一个参数则去掉 `JSON.stringify（）`即可

在Vue 3中，`this.$route.params`已经不再被支持。相反，我们可以使用`useRoute函数`来获取路由参数。

在setup()函数中使用useRoute函数，它会返回一个包含当前路由信息的响应式对象。我们可以通过访问params属性来获取路由参数。

例如：

```js
<script setup>
import { useRoute } from 'vue-router'

const route = useRoute()

console.log(route.params)
</script>
```

你将得到一个json字符串，比如你想取id（如果你传了），则可以：

```js
console.log(route.params.id)
```

获取对象的例子：

```js
const rowdata = JSON.parse(useRoute().params.row) 
console.log(rowdata)
```

[入门 | Vue Router (vuejs.org)](https://router.vuejs.org/zh/guide/)

### 状态管理

在 Vue3 中，可以使用 Vuex 来实现状态管理功能。Vuex 提供了状态管理、状态变更、状态持久化等功能，可以帮助开发人员更好地管理应用程序状态。

> 你可以把状态管理想象成一个“大管家”，他负责帮助我们管理一个项目中的所有东西。这个项目可能很大，包含很多不同的页面和功能，比如一个电商网站，里面有很多商品和购物车等等。
>
> 如果我们不使用状态管理，那么我们就需要手动处理每个页面和功能之间的数据和状态，这会很麻烦。比如，当你在商品列表页添加一个商品到购物车时，你需要把这个数据传递到购物车页面中，然后再更新购物车的状态。这样做不仅麻烦，还容易出错。
>
> 但是，如果我们使用状态管理，这些数据和状态就会被统一管理起来。我们可以把所有页面和功能需要共享的数据和状态存储到一个地方，就像一个“大仓库”一样。这样，我们就可以更方便地访问和更新这些数据和状态，而不需要手动传递它们到每个页面和功能中。
>
> 使用状态管理还有一个好处，就是更容易发现和解决问题。因为我们把所有数据和状态都存储到一个地方，所以当出现问题时，我们可以更容易地找到问题所在，并解决它。

使用Vuex前需要先在项目中安装该模块`npm install vuex@next --save`

在 Vue 3 中，使用 Vuex 4 进行状态管理时，一般会按照以下的文件夹结构来组织 Vuex 相关的文件：

```
src/
├── store/
│   ├── index.js
│   ├── state.js
│   ├── mutations.js
│   ├── actions.js
│   ├── getters.js
│   ├── modules/
│   │   ├── moduleA.js
│   │   └── moduleB.js
│   └── plugins/
│       └── logger.js
└── ...
```

其中，`store` 文件夹用于存放 Vuex 相关的文件；`index.js` 文件用于统一导出 Vuex 的 store 实例；`state.js` 文件用于定义应用的状态；`mutations.js` 文件用于定义修改状态的 mutation；`actions.js` 文件用于定义异步修改状态的 action；`getters.js` 文件用于定义获取状态的 getter；`modules` 文件夹用于存放 Vuex 模块；`plugins` 文件夹用于存放 Vuex 插件。

具体来说，可以按照以下的步骤来创建这些文件：

1. 在 `store` 文件夹下创建 `index.js` 文件，并在该文件中导入 Vue 和 Vuex，然后创建一个 Vuex 的 store 实例并导出。

```js
// store/index.js
import { createStore } from 'vuex';

const store = createStore({
  // Vuex 配置项
});

export default store;
```

2. 在 `store` 文件夹下创建 `state.js` 文件，并在该文件中定义应用的状态，即唯一数据源。

```js
// store/state.js
export default {
  // 应用的状态
};
```

3. 在 `store` 文件夹下创建 `mutations.js` 文件，并在该文件中定义修改状态的 mutation，即修改状态的唯一途径。

```js
// store/mutations.js
export default {
  // 修改状态的 mutation
};
```

4. 在 `store` 文件夹下创建 `actions.js` 文件，并在该文件中定义异步修改状态的 action。

```js
// store/actions.js
export default {
  // 异步修改状态的 action
};
```

> Actions 主要用于处理异步操作，例如 API 请求、定时器等，而 Mutations 则用于修改 State。由于异步操作是不可预测的，所以在 Actions 中进行异步操作，然后通过调用 Mutations 中的方法来修改 State，可以避免异步操作对 State 的不可控性。
>
> 具体来说，当组件需要执行一个异步操作时，它们就会调用 Actions 中的方法，Actions 中的方法可以包含任何异步操作，例如通过 Promise 或 async/await 实现异步操作，然后通过调用 Mutations 中的方法来修改 State。Mutations 中的方法是同步的，也就是说它们不能包含异步操作，因为异步操作是不可预测的，会导致状态变化的不可控性。
>
> 所以，在 Vuex 中，通常的数据流是这样的：
>
> 组件 -> Actions -> Mutations -> State
>
> 也就是说，组件通过调用 Actions 中的方法来处理异步操作，然后 Actions 中的方法通过调用 Mutations 中的方法来修改 State，最后组件可以通过访问 State 来获取数据。这种数据流的设计可以更好地管理状态和数据流，避免了状态变化的不可控性，提高了应用程序的可维护性和可测试性。

5. 在 `store` 文件夹下创建 `getters.js` 文件，并在该文件中定义获取状态的 getter。

```js
// store/getters.js
export default {
  // 获取状态的 getter
};
```

6. 如果需要拆分 Vuex 的模块，可以在 `store/modules` 文件夹下创建相应的模块文件，并在该文件中定义模块的状态、mutation、action 和 getter。

```js
// store/modules/moduleA.js
export default {
  state: {
    // 模块 A 的状态
  },
  mutations: {
    // 修改模块 A 状态的 mutation
  },
  actions: {
    // 异步修改模块 A 状态的 action
  },
  getters: {
    // 获取模块 A 状态的 getter
  }
};
```

7. 如果需要使用 Vuex 插件，可以在 `store/plugins` 文件夹下创建相应的插件文件，并在该文件中定义插件的逻辑。

```js
// store/plugins/logger.js
export default (store) => {
  // 插件的逻辑
};
```

最后，可以在应用的入口文件中导入 `store/index.js` 文件，并将其作为 Vue 的 `store` 选项传入，以便在应用中访问该 Vuex 的 store 实例。

```js
// main.js
import { createApp } from 'vue';
import store from './store';
import App from './App.vue';

createApp(App).use(store).mount('#app');
```

我们的目的是创建一个留言板，因此我们需要先创建一个留言板的状态，以保存留言板的值：

```javascript
import { createStore } from 'vuex';

export default createStore({
  state() {
    return {
      messages: [],
    };
  },
  mutations: {
    addMessage(state, message) {
      state.messages.push(message);
    },
  },
  actions: {
    addMessage(context, message) {
      context.commit('addMessage', message);
    },
  },
  getters: {
    messages: (state) => state.messages,
  },
});
```

<div align="center">store.js</div>

这个文件包含了一个 `state` 对象，用于保存留言的值。`mutations` 对象包含一个 `addMessage()` 方法，用于将新的留言添加到 `messages` 数组中。`actions` 对象包含一个 `addMessage()` 方法，用于在用户添加新的留言时调用 `addMessage()` 方法。`getters` 对象包含一个 `messages` 属性，用于获取所有留言的数组。

接下来，我们需要创建一个组件，用于显示所有留言和允许用户添加新的留言：

```vue
<template>
    <div>
      <h1>Messages</h1>
      <ul>
        <li v-for="(message, index) in messages" :key="index">
          <h2>{{ message.title }}</h2>
          <p>{{ message.content }}</p>
        </li>
      </ul>
      <form @submit.prevent="addNewMessage">
        <label for="title">Title:</label><br/>
        <input type="text" id="title" v-model="title" /><br/>
        <label for="content">Content:</label><br/>
        <textarea id="content" v-model="content"></textarea><br/>
        <button type="submit">Add Message</button>
      </form>
    </div>
  </template>
  
  <script>
  import { mapGetters, mapActions } from 'vuex';
  
  export default {
    computed: {
      ...mapGetters(['messages']),
    },
    data() {
      return {
        title: '',
        content: '',
      };
    },
    methods: {
      ...mapActions(['addMessage']),
      addNewMessage() {
        this.addMessage({
          title: this.title,
          content: this.content,
        });
        this.title = '';
        this.content = '';
      },
    },
  };
  </script>
```

<div align="center">Test_Message.vue</div>

我们在`/src`下新建文件夹`/views`以存放该组件。在模板中，我们使用 `v-for` 指令循环遍历 `messages` 数组，将每个消息的标题和内容展示出来。我们还使用 `v-model` 指令将表单元素与组件的 `title` 和 `content` 数据绑定起来。在 `data` 中，我们定义了 `title` 和 `content` 数据，用于存储用户输入的标题和内容。在 `methods` 中，我们使用 `mapActions` 方法将 `addMessage` `action` 映射到组件中。当用户提交表单时，我们调用 `addNewMessage` 方法，将用户输入的标题和内容作为参数传递给 `addMessage` `action`，并清空输入框。最后，在 `computed` 中，我们使用 `mapGetters` 方法将 `messages` `getter` 映射到组件中，以便在模板中使用它。

然后，我们需要配置路由，以导航到该组件：

```javascript
import Test_Message from './src/views/Test_Message.vue'
//......
const routes = [
    //......
    {
        path: '/message',
        name: 'messages',
        component: Test_Message,
      },
   
]
```

<div align="center">router.js</div>

最后，我们需要将状态管理和路由添加到应用程序中：

```javascript
import { createApp } from 'vue'
import App from './App.vue'
import router from '../router'
import store from './store/store'

createApp(App)
.use(router)
.use(store)
.mount('#app')
```

<div align="center">main.js</div>

### 插件和指令

在vue3我们可以使用插件和指令拓展vue3的功能。

假设我们需要实现一个页面元素滚动监听功能，当页面元素滚动到一定位置时，会触发一个事件。为了实现这个功能，我们可以使用一个名为 `v-scroll` 的自定义指令来监听页面滚动事件。

首先，我们需要安装 一个名为 `vue-scrollto` 的第三方插件，它可以帮助我们滚动到指定位置：

```bash
npm install vue-scrollto
```

然后创建一个项目，并在 `main.js` 中引入 `vue-scrollto` 插件，并创建一个名为 `v-scroll` 的自定义指令，并通过 `Vue.directive` 方法将其注册到全局：

```
import { createApp } from 'vue'
import App from './App.vue'
import VueScrollTo from 'vue-scrollto'

createApp(App)
.use(VueScrollTo)
.directive('scroll', {
    mounted(el, binding) {
      const options = binding.value || {}
      const offsetTop = options.offsetTop || 0
      window.addEventListener('scroll', () => {
        if (window.pageYOffset >= offsetTop) {
          binding.instance.$emit('scroll', window.pageYOffset)
        }
      })
    },
  })
.mount('#app')
```

<div align="center">main.js</div>

这个自定义指令会在页面元素滚动时触发一个 `scroll` 事件，并将当前页面元素的 Y 坐标作为参数传递给事件处理函数。

现在，我们可以在任何组件中使用 `v-scroll` 指令来监听页面滚动事件了。在组件中，我们可以通过 `v-scroll` 指令的参数来设置滚动监听的偏移量。

```html
<template>
  <div style="height: 80px;overflow: auto;" v-scroll="{ offsetTop: 50 }" @scroll="handleScroll">
    <p>Scroll down to see the magic happen!</p>
    <p>Scroll down to see the magic happen!</p>
    <p>Scroll down to see the magic happen!</p>
  </div>
</template>

<script>
export default {
  methods: {
    handleScroll(y) {
      console.log('Page scrolled to:', y)
    },
  },
}
</script>
```

<div align="center">App.vue</div>

在这个示例中，我们将偏移量设置为 50 像素，也就是当页面元素滚动到离顶部 50 像素的位置时，会触发 `scroll` 事件，并将当前页面的 Y 坐标传递给 `handleScroll` 方法。这就是使用插件和指令来扩展 Vue3 的功能的一个示例。通过自定义指令，我们可以轻松地实现特定的需求和功能，让我们的代码更加灵活和易于维护。

## 深入学习

### Props

在 Vue 3 中，通过 `props` 可以将父组件中的数据传递给子组件。`props` 是一个对象，可以包含多个属性，每个属性都定义了子组件中可以接收的数据的类型和默认值。我们在 “组件通信” 中学习过这一点。

> 在Vue中，我们可以把网页分成很多小部分，每个小部分都叫做一个组件。例如，我们可以把一个商品列表做成一个组件，把一个购物车做成一个组件，把一个图片轮播做成一个组件等。
>
> 在Vue3中，props是一种用来传递数据的方法。我们可以在一个组件中定义一些props，然后在这个组件的父组件中把数据传递给它。这样，这个组件就可以使用父组件传递过来的数据了。
>
> 例如：我们有一个商品列表组件，里面需要显示很多商品的信息，比如商品的名称、价格、图片等。我们可以在这个商品列表组件中定义一些props，比如`name`、`price`、`image`等。然后，在这个商品列表组件的父组件中，我们可以把每个商品的名称、价格、图片等数据传递给它。这样，商品列表组件就可以使用这些数据来显示每个商品的信息

以下是`props`的使用原则：

1.单向数据流：由于`props`的主要作用是协助父组件与子组件的通信，当父组件的`props`更新时，新的状态会流向子组件，但是子组件不能更改`props`，这会导致抛出异常。如果你仍然想修改子组件属性，那么有以下两种方法：

- 将`props`传入的值作为初始值，然后创建一个局部变量保存该初始值，后续的变化则基于这个局部变量。
- 定义一个计算属性，使用`props`中的值作为基础数据，然后在计算属性中进行进一步的转换或计算，最终返回一个新的值给组件使用。

2.`prop`校验：当我们需要确保传递给子组件的数据类型、格式等是正确的，这时就需要使用prop校验机制。在Vue组件中，我们可以通过传递一个带有props校验选项的对象来声明对传入的props的校验要求。这个对象可以设置prop的类型、是否必传、默认值等信息：

- 所有 `prop` 默认都是可选的，除非声明了 `required: true`。
- 对于除 `Boolean` 外的未传递的可选 `prop`，其值将会是 `undefined`。
- 对于 `Boolean` 类型的未传递 `prop`，其值将被转换为 `false`，而不是 `undefined`。这可以通过为它设置 `default: undefined` 来更改。
- 如果声明了 `default` 值，那么在 `prop` 的值被解析为 `undefined` 时，无论 `prop` 是未被传递还是显式指明的 `undefined`，都会改为 `default` 值。
- 当 `prop` 的校验失败后，Vue 会在控制台中抛出一个警告，以提醒开发者。

3.`Boolean`类型转换

当一个组件中声明的 `prop` 的类型为 `Boolean` 时，Vue 会对传入的该 `prop` 的值进行特殊的转换处理。具体来说，如果一个 Boolean 类型的 `prop` 被传入了一个没有设置值或者值为 true 的属性，则该 `prop` 的值会被转换为 true。如果传入的值为 false，则该 `prop` 的值会被转换为 false。例如：

```javascript
export default {
  props: {
    disabled: Boolean
  }
}

```

```vue
<!-- 等同于传入 :disabled="true" -->
<MyComponent disabled />

<!-- 等同于传入 :disabled="false" -->
<MyComponent />
```

此外，如果一个 `prop` 被声明为允许多种类型，其中包括 Boolean 类型，那么无论声明类型的顺序如何，Boolean 类型的特殊转换规则都会被应用。

### 透传Attributes

在 Vue 中，当一个组件被使用时，除了可以传递 `props` 之外，还可以使用透传 attributes 的方式向组件传递额外的 HTML 属性。透传 attributes 的意思是将外层组件中未被声明的属性值，传递给内部的子组件或者 HTML 标签。

> 使用网站或者APP时，有很多不同的页面和功能。这些页面和功能很多时候都需要使用相同的组件，比如按钮、输入框、下拉菜单等等。但是，在不同的页面和功能中，这些组件需要的属性有时候是不同的。
>
> 例如，在一个商城项目中，有很多不同的商品页面，这些商品页面都需要使用同一个“加入购物车”按钮组件。但是，不同的商品页面中，“加入购物车”按钮的颜色、大小等属性可能是不同的。
>
> 这时候，我们就需要使用透传 attributes 。透传 attributes 可以让我们在使用组件时，将一些额外的属性传递给组件内部的子组件或者 HTML 标签，从而实现更加灵活的组件开发。
>
> 比如，在上面的商城项目中，我们可以使用透传 attributes 来向“加入购物车”按钮组件传递额外的属性，比如按钮的颜色、大小等。这样，我们就可以在不同的商品页面中，使用相同的“加入购物车”按钮组件，但是可以通过透传 attributes 来设置不同的属性值，从而让按钮看起来不同。

以下为示例代码：

```vue
<template>
    <button :class="buttonClass" v-bind="$attrs">
      <slot></slot>
    </button>
  </template>
  
  <script>
  export default {
    name: 'Test_Button',
    computed: {
      buttonClass() {
        return {
          'btn': true,
          'btn-primary': this.$attrs.variant === 'primary',
          'btn-secondary': this.$attrs.variant === 'secondary',
          'btn-success': this.$attrs.variant === 'success',
          'btn-danger': this.$attrs.variant === 'danger',
          'btn-warning': this.$attrs.variant === 'warning',
          'btn-info': this.$attrs.variant === 'info',
          'btn-light': this.$attrs.variant === 'light',
          'btn-dark': this.$attrs.variant === 'dark'
        }
      }
    }
  }
  </script>
  
  <style>
  .btn {
    border-radius: 4px;
    padding: 8px 16px;
    font-size: 16px;
    cursor: pointer;
  }
  
  .btn-primary {
    color: #fff;
    background-color: #007bff;
    border-color: #007bff;
  }
  
  .btn-secondary {
    color: #fff;
    background-color: #6c757d;
    border-color: #6c757d;
  }
  
  .btn-success {
    color: #fff;
    background-color: #28a745;
    border-color: #28a745;
  }
  
  .btn-danger {
    color: #fff;
    background-color: #dc3545;
    border-color: #dc3545;
  }
  
  .btn-warning {
    color: #212529;
    background-color: #ffc107;
    border-color: #ffc107;
  }
  
  .btn-info {
    color: #fff;
    background-color: #17a2b8;
    border-color: #17a2b8;
  }
  
  .btn-light {
    color: #212529;
    background-color: #f8f9fa;
    border-color: #f8f9fa;
  }
  
  .btn-dark {
    color: #fff;
    background-color: #343a40;
    border-color: #343a40;
  }
  </style>
```

<div align="center">Test_Button.vue</div>

```vue
<template>
  <div>
    <Test_Button variant="primary">Primary Button</Test_Button>
    <Test_Button variant="secondary">Secondary Button</Test_Button>
    <Test_Button variant="success">Success Button</Test_Button>
    <Test_Button variant="danger">Danger Button</Test_Button>
    <Test_Button variant="warning">Warning Button</Test_Button>
    <Test_Button variant="info">Info Button</Test_Button>
    <Test_Button variant="light">Light Button</Test_Button>
    <Test_Button variant="dark">Dark Button</Test_Button>
  </div>
</template>

<script>
import Test_Button from './components/Test_Button.vue'

export default {
  components: {
    Test_Button
  }
}
</script>
```

<div align="center">App.vue</div>

在上面的示例中，我们定义了一个 `Button` 组件，可以通过 `variant` 属性来设置按钮的样式。然后，在使用示例中，我们使用 `Button` 组件，并分别设置了不同的 `variant` 属性，从而实现了不同样式的按钮。

在 `Button` 组件中，我们使用了 `v-bind="$attrs"` 来透传所有未被声明的属性，这样就可以让组件的子组件或者 HTML 标签访问这些透传的属性。然后，在计算属性 `buttonClass` 中，我们根据 `variant` 属性的值，返回不同的 CSS 类名，从而实现不同样式的按钮。

> 如果我们希望某些属性不被透传给子组件或者 HTML 标签，可以使用 `.sync` 修饰符来解除透传。例如，`<my-component :title.sync="title"></my-component>`，这里的 `title` 属性就不会被透传给 `my-component` 的子组件或者 HTML 标签。
>
> 另外，我们也可以在组件中使用 `inheritAttrs: false` 来禁用透传 attributes 的功能。例如，在组件选项中设置 `inheritAttrs: false`，就可以禁止该组件透传所有未被声明的属性。这样做可以提高组件的安全性，防止未知的属性被传递给组件内部的子组件或者 HTML 标签。

### 插槽Slots

在上面的例子中，我们在`Test_Button`组件使用了名为`<slot>`的标签。这就是插槽。Vue 3 中的插槽是一个非常强大的功能，可以帮助我们在组件中灵活地组合和复用内容。在上面的例子中，`<slot>`意味着插槽出口，而插槽内容则是App组件中模板内的一大串`<Test_Button>`标签内的文字内容，我们将插槽内容推送到插槽出口中。换言之，**插槽出口标示了插槽内容将在哪里被渲染。**

当你有多个插槽时，你可以使用**具名插槽**来指定你想使用的插槽：

```vue
<div class="container">
  <header>
    <slot name="header"></slot>
  </header>
  <main>
    <slot></slot>
  </main>
  <footer>
    <slot name="footer"></slot>
  </footer>
</div>
```

假设你有该BaseLayout组件，然后你可以在App组件中使用`v-slot`来指定插槽放置内容：

```vue
<BaseLayout>
  <template v-slot:header>
    <!-- header 插槽的内容放这里 -->
  </template>
</BaseLayout>
```

### 依赖注入

当我们需要从父组件向子组件传递数据时，会使用`props`。想象一下这样的结构：有一些多层级嵌套的组件，形成了一颗巨大的组件树，而某个深层的子组件需要一个较远的祖先组件中的部分数据。在这种情况下，如果仅使用 props 则必须将其沿着组件链逐级传递下去，这会非常麻烦，而且，这些居于中间的子组件有时可能也不需要这些数据。而依赖注入提供了这样一种可能性，使子孙组件能够直接得到祖先组件的数据。

> 假设你正在做一个商城项目，你需要在不同的组件中使用一些共享的数据和方法，例如用户信息、购物车数据等等。如果你在每个组件中都去请求这些数据和方法，那么代码会变得很冗长，而且如果这些数据和方法发生了变化，你需要在多个地方进行修改，非常麻烦。
>
> 这时候，就可以使用依赖注入来解决这个问题。你可以在一个祖先组件中提供这些共享的数据和方法，然后在需要使用它们的子孙组件中使用 `inject` 函数来注入这些数据和方法。这样一来，你就可以在多个组件中共享这些数据和方法，而且如果这些数据和方法发生变化，你只需要在提供它们的祖先组件中进行修改，就可以影响到所有的子孙组件。
>
> 在商城项目中，依赖注入可以用来共享一些用户信息、购物车数据等等，从而实现不同组件之间的数据共享。例如，在一个商品详情页中，你可以使用依赖注入来注入当前用户的购物车数据，从而实现添加到购物车的功能。同时，在购物车页中，你也可以使用依赖注入来注入购物车数据，并在页面中显示出来。

以下为示例代码：

```vue
<template>
    <div>
        <h3>这是子组件</h3>
        <p>欢迎，{{ username }}</p>
    </div>
</template>

<script>
import { inject } from 'vue';

export default{
    inject:['username'],
    setup(){
        return{
            //如果没有提供username，则默认值为'Guest'
            username:inject('username','Guest')
        }
    }
}
</script>
```

<div align='center'>Inject_Child.vue</div>

```vue
<template>
  <div>
    <h2>这是父组件</h2>
    <provide :username="username">
      <Inject_Child></Inject_Child>
    </provide>
  </div>
</template>
```

<div align="center">App.vue</div>

在上面的示例中，父组件通过 `provide` 函数提供了 `username` 数据，然后在子组件中使用 `inject` 函数来注入这个数据。如果父组件没有提供 `username` 数据，那么在子组件中使用 `inject` 函数时，会使用默认值 `'Guest'`。

需要注意的是，依赖注入是向下传递数据和方法的，也就是说只有子孙组件才可以通过 `inject` 函数来注入数据和方法。同时，依赖注入是通过组件的上下文相关的，也就是说只有在组件 `setup` 函数中使用 `inject` 函数才能正常工作。

如果你想确保提供的数据不能被注入方的组件更改，你可以使用 [`readonly()`](https://cn.vuejs.org/api/reactivity-core.html#readonly) 来包装提供的值。

如果你正在构建大型的应用，包含非常多的依赖提供，或者你正在编写提供给其他开发者使用的组件库，建议最好使用 Symbol 来作为注入名以避免潜在的冲突。

以下为Vue官方建议：**我们通常推荐在一个单独的文件中导出这些注入名 Symbol。**

```javascript
// keys.js
export const myInjectionKey = Symbol()

```

```vue
// 在供给方组件中
import { provide } from 'vue'
import { myInjectionKey } from './keys.js'

provide(myInjectionKey, { /*
  要提供的数据
*/ });

```

```vue
// 注入方组件
import { inject } from 'vue'
import { myInjectionKey } from './keys.js'

const injected = inject(myInjectionKey)

```

### 响应式

在 Vue 3 中，响应式是指当数据发生变化时，页面会自动更新以反映这些变化的一种机制。Vue 3 中的响应式是通过使用 `reactive` 函数来创建响应式对象，然后在模板中使用这些响应式对象来构建页面。下面是一个简单的例子：

```vue
<template>
  <div>
    <h2>{{ message }}</h2>
    <input v-model="name">
    <p>Hello, {{ name }}!</p>
  </div>
</template>

<script>
  import { reactive } from 'vue';

  export default {
    setup() {
      // 创建一个响应式对象
      const data = reactive({
        message: 'Hello, Vue 3!',
        name: ''
      });

      // 返回数据和方法
      return {
        message: data.message,
        name: data.name
      };
    }
  };
</script>
```

要在组件模板中使用响应式状态，需要在`setup()`函数中定义并返回。在上面的示例中，我们使用 `reactive` 函数来创建一个响应式对象 `data`，其中包含了一个字符串类型的 `message` 属性和一个空字符串类型的 `name` 属性。然后在模板中，我们使用 `v-model` 指令将 `name` 属性绑定到一个输入框上，并在页面中显示出来。同时，我们还将 `message` 属性展示在页面中。

需要注意的是，当我们使用 `reactive` 函数来创建一个响应式对象时，只有对象中已经存在的属性才会被转化为响应式属性。如果在后续的使用中我们需要添加一个新的属性，我们需要使用 `ref` 函数来将它转化为响应式属性。ref()方法允许我们使用任何值类型的响应式ref。下面是一个简单的例子：

```vue
<template>
  <div>
    <h2>{{ message }}</h2>
  </div>
</template>

<script>
  import { ref } from 'vue';

  export default {
    setup() {
      // 创建一个响应式变量
      const message = ref('Hello, Vue 3!');

      // 修改变量的值
      message.value = 'Hello, World!';

      // 返回数据
      return {
        message: message.value
      };
    }
  };
</script>
```

在上面的示例中，我们使用 `ref` 函数来创建一个响应式变量 `message`，并将它的初始值设置为字符串 `'Hello, Vue 3!'`。然后我们通过访问 `.value` 属性来修改它的值，并在模板中展示它的值。

如果我们没有使用 `ref` 函数，那么创建的变量就不是响应式的，Vue 3 是无法监听它的变化的。下面是一个没有使用 `ref` 函数的示例：

```vue
<template>
  <div>
    <h2>{{ message }}</h2>
  </div>
</template>

<script>
  export default {
    setup() {
      // 创建一个普通变量
      let message = 'Hello, Vue 3!';

      // 修改变量的值
      message = 'Hello, World!';

      // 返回数据
      return {
        message
      };
    }
  };
</script>
```

在上面的示例中，我们使用 `let` 关键字来创建一个普通变量 `message`，并将它的初始值设置为字符串 `'Hello, Vue 3!'`。然后我们直接修改变量的值，并在模板中展示它的值。

需要注意的是，如果我们使用了一个普通变量而不是响应式变量，那么当这个变量的值发生变化时，Vue 3 是无法监听它的变化的，页面也不会自动更新以反映这些变化。因此，**在开发 Vue 3 应用程序时，建议尽可能使用 `ref` 函数来创建响应式变量，以便更好地利用 Vue 3 的响应式机制。**

`<script setup>`是 Vue 3 中的一个新特性，它可以让我们更轻松地编写组件逻辑。使用 `<script setup>` 标签可以将组件的 `props`、`data`、`computed`、`methods` 等相关逻辑都放在一个地方，从而让代码更加简洁易读。

具体来说，`<script setup>` 标签可以让我们在组件中使用以下语法糖：

- `props`：可以通过解构赋值的方式，直接将父组件传递下来的 `props` 属性解构出来。
- `setup`：可以在这个函数中编写组件的逻辑代码，包括响应式数据、计算属性、方法等。
- `defineComponent`：可以使用这个函数来定义组件，而不需要在组件的选项中手动指定 `props`、`data`、`computed`、`methods` 等。
- `$emit`：可以使用这个函数来触发一个自定义事件，向父组件传递数据。

下面是一个使用 `<script setup>` 标签的简单例子，假设有一个父组件，其中含有titile属性：

```vue
<template>
  <div>
    <h2>{{ message }}</h2>
    <button @click="increaseCount">{{ count }}</button>
  </div>
</template>

<script setup>
  import { ref } from 'vue';

  // 解构赋值 props
  const { title } = props;

  // 创建响应式数据
  const message = ref('Hello, Vue 3!');
  const count = ref(0);

  // 定义方法
  function increaseCount() {
    count.value++;
  }

  // 导出组件
  export default {
    setup() {
      // 返回数据
      return {
        message,
        count,
        increaseCount
      };
    }
  };
</script>
```

在上面的示例中，我们使用 `<script setup>` 标签来编写组件逻辑。首先，我们通过解构赋值的方式，将父组件传递下来的 `props` 属性解构出来，然后创建了两个响应式数据 `message` 和 `count`，以及一个方法 `increaseCount`。最后，我们使用 `setup` 函数来返回数据，将它们暴露给模板使用。

需要注意的是，使用 `<script setup>` 标签编写组件时，不需要手动指定组件的名称、`props`、`data`、`computed`、`methods` 等选项，这些选项会被自动合并到组件的定义中。此外，使用 `<script setup>` 标签编写组件时，也不能使用 `this` 关键字来访问组件实例，而是需要使用解构赋值的方式来访问组件的属性和方法。

如果在 Vue 3 中没有使用 `<script setup>` 标签，那么我们需要手动定义组件的选项，例如 `props`、`data`、`computed`、`methods` 等。这些选项需要在组件的选项中进行手动指定，而不是在 `<script>` 标签中使用语法糖的方式来定义。

下面是一个没有使用 `<script setup>` 的简单示例：

```vue
<template>
  <div>
    <h2>{{ message }}</h2>
    <button @click="increaseCount">{{ count }}</button>
  </div>
</template>

<script>
  import { ref } from 'vue';

  export default {
    // 手动指定 props、data、methods 等选项
    props: {
      title: String
    },
    data() {
      return {
        message: 'Hello, Vue 3!',
        count: 0
      };
    },
    methods: {
      increaseCount() {
        this.count++;
      }
    }
  };
</script>
```

在上面的示例中，我们没有使用 `<script setup>` 标签，而是手动指定了组件的 `props`、`data`、`methods` 等选项。在 `data` 函数中，我们需要手动返回一个对象，这个对象包含组件的响应式数据。在 `methods` 对象中，我们需要手动指定组件的方法。

需要注意的是，与使用 `<script setup>` 相比，手动指定组件的选项会使代码变得更加冗长，而且需要手动管理组件的选项，容易出现错误。因此，**在开发 Vue 3 应用程序时，建议尽可能使用 `<script setup>` 标签来编写组件逻辑，以提高代码的简洁性和可读性**。

### 异步组件

在 Vue 3 中，异步组件是一种特殊的组件，它可以在需要时进行延迟加载，从而提高应用程序的性能。异步组件可以在需要时动态地加载组件代码和模板，而不是在应用程序初始化时就将所有组件都加载到内存中。

> 一个网页中会有很多组件，但并不是所有的组件都需要在一开始就加载。而是只有当你需要用到某个组件的时候，才会去加载它。这样可以减少网页的加载时间，让网页更快地响应。
>
> 在商城项目中，异步组件可以用来优化网页性能。比如，在商城项目中，可能会有很多商品列表需要显示，如果直接加载所有商品的列表，那么网页的加载时间就会很长。但是如果只在需要显示某个商品的时候再去加载它的商品列表，那么就可以提高网页的性能。
>
> 另外，商城项目中可能会有很多不同的页面，比如商品列表页、商品详情页、购物车页面等等。这些页面中可能会包含很多组件，如果一开始就将所有组件都加载出来，就会占用很多内存。但是如果使用异步组件，就可以让每个页面只加载它需要的组件，从而减少内存的占用，提高网页的性能和响应速度。
>
> 异步组件是一个很有用的工具，它可以帮助我们优化网页性能，让网页更快地响应。在实际项目中，我们可以根据具体情况来选择使用异步组件，从而提高网页的性能和用户体验。

以下为示例代码：

```vue
<template>
  <div>
    <component :is="AsyncComponent" />
  </div>
</template>

<script>
import { defineAsyncComponent } from 'vue';
import Async_Loading from './components/Async_Loading.vue'
import Async_ErrorComponent from './components/Async_ErrorComponent.vue'
    
export default {
  name: 'App',
  setup() {
    const AsyncComponent = defineAsyncComponent({
      // 异步加载组件代码和模板
      loader: () => import('./components/AsyncText.vue'),
      // 加载组件时显示的占位符
      loadingComponent: Async_Loading,
      // 加载组件失败时显示的占位符
      errorComponent: Async_ErrorComponent,
      // 加载组件的延迟时间，默认为 200ms
      delay: 200,
      // 最长等待时间，超过该时间显示错误占位符，默认为 Infinity
      timeout: 3000
    });
    return {
      AsyncComponent
    }
  }
}
</script>
```

<div align="center">App.vue</div>

```vue
<template>
    <div>
        该组件已加载完成
    </div>
</template>
<script>
export default {
  name: 'AsyncTest',
  created() {
    setTimeout(() => {
      console.log('Component loaded!');
    }, 3000);
  }
}
</script>
```

<div align='center'>AsyncTest.vue</div>

```vue
<template>
    <div>
      <h3>Loading...</h3>
    </div>
  </template>
  
  <script>
  export default {
    name: 'Async_Loading'
  }
  </script>
```

<div align='center'>Async_Loading.vue</div>

```vue
<template>
    <div>
      <h3>Oops! Something went wrong!</h3>
    </div>
  </template>
  
  <script>
  export default {
    name: 'Async_ErrorComponent'
  }
  </script>
```

<div align='center'>Async_ErrorComponent.vue</div>

### 组合式函数

在 Vue 3 中，组合式函数（Composition Functions）是一种用于定义组件逻辑的新方式。它允许你将组件的逻辑拆分为多个可重用的函数，并在组件中进行组合，以实现更好的代码复用和组件测试。组合式函数是建立在 Vue 3 的响应式系统之上的，这意味着你可以在函数中使用 `ref`、`reactive`、`computed` 等响应式 API，来实现组件的响应式数据处理。

以下是一些常用的组合式函数：

1. `setup` 函数：`setup` 函数是组合式函数的入口点，用于定义组件的逻辑。你可以在 `setup` 函数中返回一个对象，该对象可以包含组件的数据、方法、生命周期钩子等内容。在 `setup` 函数中，你可以使用 `ref`、`reactive`、`computed` 等响应式 API 来处理组件的数据。
2. `ref` 函数：`ref` 函数用于创建一个响应式的数据引用，它可以被用于存储和更新组件中的数据。`ref` 函数会返回一个具有 `value` 属性的对象，该属性可以被用于读取和设置数据的值。
3. `reactive` 函数：`reactive` 函数用于创建一个响应式的对象，它可以被用于存储和更新组件中的数据。`reactive` 函数会返回一个响应式的对象，该对象的属性可以被用于读取和设置数据的值。
4. `computed` 函数：`computed` 函数用于创建一个计算属性，它会根据依赖的响应式数据自动计算出一个新的值。`computed` 函数会返回一个具有 `value` 属性的对象，该属性可以被用于读取计算属性的值。

组合式函数的优点在于它能够让你更加灵活地组织组件的逻辑，使得代码更加清晰、易于维护和测试。同时，由于组合式函数的实现方式和 Vue 3 的响应式系统密切相关，因此它也能够提高组件的性能和响应速度。

> 组合式函数就像是一堆积木，你可以拿它们来搭建一个高楼大厦。在商城项目中，我们需要做很多事情，比如显示商品信息、添加商品到购物车、结算等等。这些事情就像是积木一样，我们可以把它们拼成一个商城网站。组合式函数就是我们拼积木的工具。我们可以用组合式函数来写一些小的积木，比如显示商品信息的积木、添加商品到购物车的积木、结算的积木等等。然后，我们可以把这些小的积木组合在一起，就可以搭建出一个完整的商城网站。
>
> 组合式函数在商城项目中的作用非常重要，它可以让我们更加灵活地组织代码，使得代码更加清晰、易于阅读和维护。同时，它还可以提高我们的开发效率，让我们更快地完成商城网站的开发。比如，在商城项目中，我们可以使用组合式函数来实现以下功能：
>
> 1. 显示商品信息：我们可以写一个显示商品信息的组合式函数，这个函数可以接受商品数据作为参数，然后渲染出商品的名称、价格、图片等信息。
> 2. 添加商品到购物车：我们可以写一个添加商品到购物车的组合式函数，这个函数可以接受商品数据和购物车数据作为参数，然后将商品添加到购物车中。
> 3. 结算：我们可以写一个结算的组合式函数，这个函数可以接受购物车数据作为参数，然后计算出购物车中的商品总价和运费等信息。
>
> 通过使用组合式函数，我们可以更加方便地组织代码，使得代码更加易于维护和扩展。同时，我们也可以更加清晰地分离出不同的功能模块，让代码更加易于理解和阅读。

以下为示例代码：

```javascript
import { ref } from 'vue';

export default function useRandomNumbers() {
  // 定义响应式数据
  const numbers = ref([]);

  // 生成随机数
  function generateNumbers() {
    for (let i = 0; i < 10; i++) {
      numbers.value.push(Math.floor(Math.random() * 100));
    }
  }

  // 计算平均值
  function calculateAverage() {
    const sum = numbers.value.reduce((acc, cur) => acc + cur, 0);
    return sum / numbers.value.length;
  }

  // 返回响应式数据和方法
  return {
    numbers,
    generateNumbers,
    calculateAverage
  };
}
```

<div align="center">useRandomNumbers.js</div>

```vue
<template>
  <div>
    <button @click="generateNumbers">Generate Random Numbers</button>
    <div v-if="numbers.length">
      <p>Numbers: {{ numbers.join(', ') }}</p>
      <p>Average: {{ calculateAverage() }}</p>
    </div>
  </div>
</template>

<script>
import useRandomNumbers from './useRandomNumbers';

export default {
  setup() {
    // 使用组合式函数
    const { numbers, generateNumbers, calculateAverage } = useRandomNumbers();

    // 返回响应式数据和方法
    return {
      numbers,
      generateNumbers,
      calculateAverage
    };
  }
};
</script>
```

<div align='center'>App.vue</div>

在这段代码中，我们使用 `import` 引入了刚刚定义的 `useRandomNumbers` 组合式函数，并在 `setup` 函数中使用它，从而获取到响应式数据和方法。然后，我们可以在模板中使用这些数据和方法，以显示随机数和平均值。

### 自定义指令

自定义指令主要是为了重用涉及普通元素的底层 DOM 访问的逻辑。自定义指令由两个部分组成：指令名称和指令定义对象。指令定义对象包括了多个钩子函数，这些钩子函数可以在不同的生命周期中对指令进行操作。下面是一个自定义指令的例子，当一个 input 元素被 Vue 插入到 DOM 中后，它会被自动聚焦：

```vue
<script setup>
// 在模板中启用 v-focus
const vFocus = {
  mounted: (el) => el.focus()
}
</script>

<template>
  <input v-focus />
</template>

```

自定义指令可以用于很多场景，例如：

- 在元素上添加一些特殊的行为，例如实现无限滚动、拖拽等功能；
- 对元素进行 DOM 操作，例如修改样式、添加事件监听器等；
- 对元素进行动态绑定，例如根据数据绑定不同的样式、属性等。

指令钩子是在自定义指令中定义的一组函数，它们定义了指令在不同生命周期中的行为。

在 Vue.js 中，指令钩子分为如下几个：

- `bind`: 只调用一次，在指令绑定到元素上时调用，可以在这里进行一次性的初始化设置。

- `inserted`: 被绑定元素插入父节点时调用（仅保证父节点存在，但不一定已被插入文档中），可以在这里进行 DOM 操作。

- `update`: 指令所在的 VNode 更新时调用，但可能发生在其子 VNode 更新之前。指令的值可能发生了变化，也可能没有。但你可以通过比较绑定的值来忽略不必要的模板更新。

- `componentUpdated`: 指令所在的 VNode 及其子 VNode 全部更新后调用。可以在这里进行 DOM 操作。

- `unbind`: 只调用一次，在指令从元素上解绑时调用，可以在这里进行清理工作。

这些钩子函数可以在自定义指令中使用，以便在指令的不同生命周期中对指令进行操作。例如，在 `bind` 钩子中可以进行一次性的初始化设置，而在 `update` 钩子中可以根据新的值对元素进行更新。

以下是一个自定义指令的例子，展示了如何使用指令钩子：

```javascript
Vue.directive('my-directive', {
  bind: function(el, binding, vnode) {
    // 在元素绑定到指令时调用
    // 可以在这里进行一次性的初始化设置
  },
  inserted: function(el, binding, vnode) {
    // 在元素插入到 DOM 树中时调用
    // 可以在这里进行 DOM 操作
  },
  update: function(el, binding, vnode) {
    // 在指令所在的 VNode 更新时调用
    // 可以在这里根据新的值对元素进行更新
  },
  componentUpdated: function(el, binding, vnode) {
    // 在指令所在的 VNode 及其子 VNode 全部更新后调用
    // 可以在这里进行 DOM 操作
  },
  unbind: function(el, binding, vnode) {
    // 在指令从元素上解绑时调用
    // 可以在这里进行清理工作
  }
})
```

总之，指令钩子可以让开发者在自定义指令中定义不同生命周期中的行为，从而实现更加灵活和强大的自定义指令功能。

自定义指令始终作用于根节点，Vue官方建议：

当应用到一个多根组件时，指令将会被忽略且抛出一个警告。和 attribute 不同，指令不能通过 `v-bind="$attrs"` 来传递给一个不同的元素。总的来说，**不推荐在组件上使用自定义指令。**

### Axios

我们以高德提供的天气API为例，在Vue3中实现Ajax：

[天气查询]: https://lbs.amap.com/api/webservice/guide/api/weatherinfo/#t1

在Vue3使用Ajax可以在项目内安装第三方库Axios：

```shell
npm install axios
```

在Vue中创建 `gd_api.js` 文件：

```javascript
import axios from 'axios'

export function fetchData(city) {
  return axios.get('https://restapi.amap.com/v3/weather/weatherInfo', {
    params: {
      city: city,
      key: '<用户key>'
    }
  })
  .then(response => response.data)
  .catch(error => {
    console.error(error)
  })
}
```

<div align='center'>gd_api.js</div>

以组合式函数的形式，在App.vue组件中调用`fetchData`函数并将响应结果的lives值添加至模板：

```vue
<template>
    <div>
        <button @click="fetchData">发送请求</button>
        <p v-if="response">{{ response.lives }}</p>
      </div><hr/>
</template>
<script>
import{ fetchData } from "./gd_api"

export default {
  data() {
    return {
      response: ''
    }
  },
  mounted(){
    fetchData('110101')
    .then(data=>{
      this.response = data
    })
  }
}
</script>
```

<div align='center'>App.vue</div>

## 拓展学习

### 内部组件

#### Transition

`<Transition>` 会在一个元素或组件进入和离开 DOM 时应用动画：

[Transition]: https://cn.vuejs.org/guide/built-ins/transition.html

#### TransitionGroup

`<TransitionGroup>` 是一个内置组件，用于对 `v-for` 列表中的元素或组件的插入、移除和顺序改变添加动画效果：

[TransitionGroup]: https://cn.vuejs.org/guide/built-ins/transition-group.html

#### KeepAlive

`<KeepAlive>` 是一个内置组件，它的功能是在多个组件间动态切换时缓存被移除的组件实例：

[KeepAlive]: https://cn.vuejs.org/guide/built-ins/keep-alive.html

#### Teleport

`<Teleport>` 是一个内置组件，它可以将一个组件内部的一部分模板“传送”到该组件的 DOM 结构外层的位置去：

[Teleport]: https://cn.vuejs.org/guide/built-ins/teleport.html

### 测试

在 Vue 中学习如何使用测试：

[测试]: https://cn.vuejs.org/guide/scaling-up/testing.html

### 服务端渲染（SSR）

Vue3的SSR（Server-Side Rendering，服务端渲染）是一种将Vue应用程序在服务器端渲染成HTML字符串，然后将其发送到客户端浏览器的技术。通过SSR，可以提高应用程序的首次加载速度和SEO（Search Engine Optimization，搜索引擎优化）效果。需要注意的是，在使用SSR时，我们需要将Vue应用程序中的一些特定代码进行修改，例如将Vue组件中的异步数据获取改为同步获取，以便在服务器端渲染时能够获取到所有必要的数据。

[服务端渲染SSR]: https://cn.vuejs.org/guide/scaling-up/ssr.html

### 使用Vue CLI生产部署

Vue3的生产部署是指将Vue应用程序部署到生产环境中的过程，以便用户能够访问和使用该应用程序。在生产部署过程中，需要进行以下几个步骤：

1. 构建生产环境版本

在生产环境中，我们需要使用Vue应用程序的生产环境版本，该版本不包含开发环境中的调试代码和警告信息，可以提高应用程序的性能和稳定性。在Vue3中，可以使用以下命令来构建生产环境版本：

```bash
npm run build
```

该命令会将Vue应用程序编译成静态文件，并将这些文件打包到`dist`目录中。

​	2.配置服务器环境

在生产环境中，我们需要将Vue应用程序部署到服务器上，并配置服务器环境。例如，需要配置服务器的端口号、静态文件目录、反向代理等。具体的配置方式取决于服务器的类型和环境，可以参考相关的文档进行配置。

​	3.部署Vue应用程序

在配置好服务器环境之后，我们需要将Vue应用程序部署到服务器上。具体的部署方式取决于服务器的类型和环境，可以使用FTP、SSH等工具将应用程序上传到服务器上，也可以使用容器化技术将应用程序部署到云端等。

​	4.启动应用程序

在部署完Vue应用程序之后，我们需要启动应用程序，以便用户能够访问和使用该应用程序。具体的启动方式取决于服务器的类型和环境，可以使用命令行或者面板工具等进行启动。

参考官方文档：

[Vue CLI]: https://cli.vuejs.org/zh/guide/

### 安全

参考官方文档：

[安全]: https://cn.vuejs.org/guide/best-practices/security.html

## 推荐阅读

[《Vue.js设计与实现》霍春阳]: https://weread.qq.com/web/bookDetail/c5c32170813ab7177g0181ae

## 文档部分源码

[VueStudy_Test]: https://github.com/organwalk/vuestudy_test

