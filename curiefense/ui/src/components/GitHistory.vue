<template>
  <section class="version-history">
    <div class="mb-0"
         :class="{card: isCollapsible}">
      <p class="title is-6 is-expanded"
         v-if="!isCollapsible">
        Version History
      </p>
      <header class="card-header"
              v-else>
        <p class="card-header-title collapsible-header">
          <a @click="toggleAccordionCollapsed"
             :class="{'is-active': !isAccordionCollapsed}">
            <i class="arrow mr-2"
               :class="[isAccordionCollapsed ? 'down' : 'up']" />
            {{ isAccordionCollapsed ? 'Show' : 'Hide' }} Version History
          </a>
        </p>
      </header>
      <div class="version-history-content"
           :class="{'is-active': !isAccordionCollapsed, 'is-collapsible': isCollapsible}">
        <span class="is-family-monospace">{{ apiPath }}</span>
        <div class="pt-4"
             :class="{'card-content pl-4': isCollapsible}">
          <div class="content">
            <button class="button is-outlined is-text is-loading is-100"
                    v-if="loading">
              Loading
            </button>
            <template v-else-if="viewData.length">
              <table class="table is-striped">
                <thead>
                  <tr>
                    <th class="is-size-7 is-11"
                      :class="thSortableClass('date')"
                      @click="columnToggleSort('date')">
                      <span>Date</span>
                    </th>
                    <th class="is-size-7 is-11">
                      Time (UTC)
                    </th>
                    <th class="is-size-7 is-10"
                      :class="thSortableClass('version')"
                      @click="columnToggleSort('version')">
                      Version
                    </th>
                    <th class="is-size-7 is-40"
                      :class="thSortableClass('message')"
                      @click="columnToggleSort('message')">
                      Message
                    </th>
                    <th class="is-size-7 is-15"
                      :class="thSortableClass('author')"
                      @click="columnToggleSort('author')">
                      Author
                    </th>
                    <th class="is-size-7 is-13" />
                  </tr>
                </thead>
                <tbody>
                  <template v-for="{version, date, message, email, author, parents} in commits">
                    <tr :key="version">
                      <td class="is-size-7 is-vcentered py-3 is-11"
                          :title="formatDate(date)">
                        {{ formatDate(date) }}
                      </td>
                      <td class="is-size-7 is-vcentered py-3 is-11"
                          :title="formatTime(date)">
                        {{ formatTime(date) }}
                      </td>
                      <td class="is-size-7 is-vcentered py-3 is-10"
                          :title="version">
                        {{ version.substr(0, 7) }}
                      </td>
                      <td class="is-size-7 is-vcentered py-3 is-40">{{ message }}</td>
                      <td class="is-size-7 is-vcentered py-3 is-15">{{ author }}</td>
                      <td class="is-size-7 is-vcentered actions-cell is-13 has-text-right">
                        <button class="button is-small restore-button"
                                @click="restoreVersion(version)"
                                tabindex="1"
                                title="Restore version">
                          <span class="icon is-small">
                            <i class="fas fa-history" />
                          </span>
                        </button>
                        <button class="button is-small view-details ml-3"
                                :class="{'is-loading': loadingDiffs === version}"
                                @click="toggleCommitDetails(version, parents)"
                                tabindex="1"
                                :title="`${isCommitCollapsed(version) ? 'Show' : 'Hide'} details`">
                          <span class="icon is-small"
                                v-if="loadingDiffs !== version">
                            <i class="arrow"
                               :class="[isCommitCollapsed(version) ? 'down' : 'up']" />
                          </span>
                        </button>
                      </td>
                    </tr>
                    <tr v-if="!isCommitCollapsed(version)"
                        class="commit-details-header"
                        :key="`${version}-details-header`">
                      <td class="py-0 px-0"
                          colspan="6">
                        <a @click="toggleChangesLog(version)">
                          <span class="is-family-monospace">
                            <i class="arrow mr-3"
                               :class="[version === viewCommitChanges ? 'up' : 'down']"
                               :title="`${version === viewCommitChanges ? 'Hide' : 'Show'} changes`" />
                            {{ apiPath }}
                          </span>
                        </a>
                      </td>
                    </tr>
                    <template v-if="version === viewCommitChanges">
                      <tr v-if="differences && Object.keys(differences).length"
                          class="commit-changes"
                          :key="`${version}-changes`">
                        <td class="py-0 px-0"
                            colspan="6">
                          <table class="table">
                            <tbody>
                              <tr v-for="(change, key) in differences[version].added" :key="`${version}-${key}-add`">
                                <td class="is-vcentered has-text-centered px-0 py-0 is-10 addition">
                                  +
                                </td>
                                <td class="pl-3 py-0 is-size-7 is-90">
                                  {{ key }}: {{ change }}
                                </td>
                              </tr>
                              <tr v-for="(change, key) in differences[version].deleted" :key="`${version}-${key}-del`">
                                <td class="is-vcentered has-text-centered px-0 py-0 is-10 deletion">
                                  -
                                </td>
                                <td class="pl-3 py-0 is-size-7 is-90">
                                  {{ key }}: {{ change }}
                                </td>
                              </tr>
                              <template v-for="(change, key) in differences[version].updated">
                                <tr :key="`${version}-${key}-upd`">
                                  <td class="is-vcentered has-text-centered px-0 py-0 is-10 addition">
                                    +
                                  </td>
                                  <td class="pl-3 py-0 is-size-7 is-90">
                                    {{ key }}: {{ change.current }}
                                  </td>
                                </tr>
                                <tr :key="`${version}-${key}-upd-del`">
                                  <td class="is-vcentered has-text-centered px-0 py-0 is-10 deletion">
                                    -
                                  </td>
                                  <td class="pl-3 py-0 is-size-7 is-90">
                                    {{ key }}: {{ change.parent }}
                                  </td>
                                </tr>
                              </template>
                            </tbody>
                          </table>
                        </td>
                      </tr>
                      <tr v-else
                          class="commit-changes"
                          :key="`no-${version}-changes`">
                        <td class="is-size-7 is-100"
                            colspan="6">
                          No changes found
                        </td>
                      </tr>
                    </template>
                    <tr v-if="!isCommitCollapsed(version)"
                        class="commit-details"
                        :key="`${version}-details`">
                      <td class="is-size-7 py-3 is-11 has-text-weight-bold">
                        <div>Date:</div>
                        <div>Time:</div>
                        <div>Version:</div>
                        <div>Parents:</div>
                      </td>
                      <td class="is-size-7 py-3 is-11">
                        <div>{{ formatDate(date) }}</div>
                        <div>{{ formatTime(date) }}</div>
                        <div>{{ version.substr(0, 7) }}</div>
                        <div>
                          <p v-for="parent in parents"
                             :key="parent"
                             :title="parent">
                            {{ parent.substr(0, 7) }}
                          </p>
                        </div>
                      </td>
                      <td class="is-size-7 py-3 is-10 has-text-weight-bold">
                        <div>Message:</div>
                        <div>Author:</div>
                        <div>API:</div>
                      </td>
                      <td colspan="3"
                          class="is-size-7 py-3">
                        <div>{{ message }}</div>
                        <div>{{ author }}</div>
                        <div>{{ email }}</div>
                      </td>
                    </tr>
                  </template>
                </tbody>
              </table>
              <div class="load-more card-content py-3 pl-3"
                   v-if="viewData.length > maxRows">
                <a class="button is-small is-info is-light"
                   @click="loadMore">
                   Load More
                </a>
              </div>
            </template>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script lang="ts">
import Vue, {PropType} from 'vue'
import {Commit} from '@/types'
import DateTimeUtils from '@/assets/DateTimeUtils'
import _ from 'lodash'

const MAX_ROWS = 5

export default Vue.extend({

  name: 'GitHistory',

  props: {
    gitLog: Array as PropType<Commit[]>,
    apiPath: String,
    loading: Boolean,
    loadingDiffs: String,
    differences: Object,
    isCollapsible: {
      type: Boolean,
      default: true,
    },
  },

  data() {
    return {
      isAccordionCollapsed: true,
      maxRows: MAX_ROWS,
      viewCommit: undefined,
      viewCommitChanges: undefined,
      sort: {} as {
        field?: keyof Commit,
        desc?: boolean,
      },
      viewData: this.gitLog,
    }
  },

  watch: {
    gitLog: {
      handler(newVal, oldVal) {
        if (!_.isEqual(newVal, oldVal)) {
          this.viewData = newVal
          this.sort = {
            field: 'date',
            desc: true,
          }
          this.sortData()
        }
      },
      deep: true,
    },
  },

  computed: {
    commits(): Commit[] {
      return this.viewData.slice(0, this.maxRows)
    },
    isSortable(): boolean {
      return this.viewData.length > 1
    },
  },

  methods: {
    restoreVersion(versionId: Commit['version']) {
      this.$emit('restore-version', versionId)
    },

    formatDate(date: string) {
      return DateTimeUtils.isoToNowDateCuriefenseFormat(date)
    },

    formatTime(date: string) {
      return DateTimeUtils.isoToNowTimeCuriefenseFormat(date)
    },

    toggleAccordionCollapsed() {
      this.isAccordionCollapsed = !this.isAccordionCollapsed
      this.viewCommit = undefined
      this.viewCommitChanges = undefined
      if ( !this.isAccordionCollapsed ) {
        this.maxRows = MAX_ROWS
      }
    },

    toggleCommitDetails(versionId: Commit['version'], parents: Commit['parents']) {
      if ( this.isCommitCollapsed(versionId)) {
        this.viewCommit = versionId
        this.$emit('show-changes', versionId, parents)
      } else {
        this.viewCommit = undefined
      }
      this.viewCommitChanges = undefined
    },

    toggleChangesLog(versionId: Commit['version']) {
      this.viewCommitChanges = this.viewCommitChanges !== versionId ? versionId : undefined
    },

    isCommitCollapsed(versionId: Commit['version']) {
      return this.viewCommit !== versionId || this.loadingDiffs === versionId
    },

    columnToggleSort(colName: keyof Commit) {
      if ( !this.isSortable ) {
        this.sort = {}
        return
      }
      if (colName === this.sort.field) {
        this.sort.desc = !this.sort.desc
      } else {
        this.sort = {
          field: colName,
          desc: true,
        }
      }
      this.sortData();
    },

    sortData() {
      const sortedData = _.sortBy( this.viewData, this.sort.field )
      this.viewData = this.sort.desc ? sortedData.reverse() : sortedData
    },

    thSortableClass(fieldName: keyof Commit) {
      const result = this.isSortable ? ['sortable'] : []
      if ( this.sort.field === fieldName ) {
        result.push( this.sort.desc ? 'desc' : 'asc' )
      }
      return result
    },

    loadMore() {
      this.maxRows += MAX_ROWS
    },
  },
})
</script>
<style scoped lang="scss">

.is-collapsible {
  max-height: 0;
  overflow-y: hidden;
  transition: max-height 0.2s ease-out;

  &.is-active {
    max-height: 1000px;
    transition: max-height 0.2s ease-in;
  }
}

.version-history-content .is-family-monospace {
  align-items: center;
  background-color: #f5f5f5;
  color: #737373;
  display: flex;
  height: 32px;
  padding-left: 1rem;
}

.version-history .arrow {
  border: solid #111;
  border-width: 0 2px 2px 0;
  display: inline-block;
  padding: 4px;

  &.up {
    margin-bottom: -2px;
    transform: rotate(-135deg);
  }

  &.down {
    margin-bottom: 2px;
    transform: rotate(45deg);
  }
}

.view-details {
  width: 2.5em;
}

.actions-cell {
  $actions-color: #014ac6;

  .button {
    color: $actions-color;
  }

  .button .arrow {
    border-color: $actions-color;
  }
}

.content .card-header-title.collapsible-header {
  margin-bottom: 0;

  a {
    color: #000;
    font-family: 'Red Hat Display', sans-serif;
    font-size: 14px;
    font-style: normal;
    font-weight: 400;
    width: 100%;
  }
}

.is-100 .columns > .column {
  flex: 1 1 auto;
}

.commit-details td div {
  margin-bottom: 5px;
}

.version-history .commit-details-header .arrow {
  border-color: #787c80;
  margin-bottom: -5px;

  &.down {
    margin-bottom: 4px;
  }
}

.commit-changes {
  td {
    background-color: #fff;
    border: 0;
  }

  .addition {
    background-color: #ebf9ef;
  }

  .deletion {
    background-color: #fce6ee;
  }

  table tbody {
    display: block;
    max-height: 5.5em;
    overflow: auto;
  }
}

.version-history-content .sortable {
  cursor: pointer;
  position: relative;

  span {
    float: left;
  }

  &::before,
  &::after {
    border: solid #555;
    border-width: 0 1px 1px 0;
    content: '';
    display: inline-block;
    height: 7px;
    position: absolute;
    right: 5px;
    top: 50%;
    width: 7px;
  }

  &::before {
    margin-top: -5px;
    transform: rotate(-135deg);
  }

  &::after {
    margin-top: -1px;
    transform: rotate(45deg);
  }

  &.desc::before {
    display: none;
  }

  &.desc::after {
    margin-top: -5px;
  }

  &.asc::before {
    margin-top: -2px;
  }

  &.asc::after {
    display: none;
  }
}

.load-more {
  background-color: #edeef0;
}

</style>
